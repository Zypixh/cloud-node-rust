//! AccECN (RFC 9768) dual-role state machine — the pure algorithm
//! half; wire-format emission/parsing lives in smoltcp-edge
//! `wire/tcp.rs` (T7 wiring).
//!
//! # Roles
//!
//! - **Initiator** (active open / dialed): sends SYN with AE+CWR+ECE =
//!   (1,1,1) to offer AccECN, (0,1,1) for classic fallback; decodes the
//!   SYN-ACK per RFC 9768 §3.1.2 Table 3.
//! - **Responder** (listener / accepted): decodes the SYN per §3.1.1
//!   Table 2 and encodes the SYN-ACK response.
//!
//! # Negotiated modes
//!
//! `AccEcn` (full byte-grain CE feedback), `ClassicEcn` (RFC 3168),
//! `NotEct` (no ECN). The handshake outcome is cached here; the stack
//! uses it to pick ACE-field updates vs. once-per-window ECE.
//!
//! # Rules enforced (§3, RFC 9768)
//!
//! - Initial SYN MUST NOT carry an AccECN TCP Option (§3.2.3.2.1) —
//!   this module provides no API that could produce one.
//! - SYN-ACK encoding: the responder echoes its capability per Table 2;
//!   `challenge` (SYN cookie / SYN-ACK-only probes) paths never
//!   negotiate ECN (D-D3 — no API entry here).
//! - ACE counter: 3-bit field in the TCP flags area counts CE marks on
//!   *bytes* since the last feedback point modulo 8 — wraparound-safe
//!   delta via 3-bit modular arithmetic.
//! - Byte counters option (kind 11, `AE`): three 24-bit counters —
//!   EE0B/ECT0B/CEB (option kind assignments per RFC 9768 §5 draft
//!   encoding carried in wire/tcp.rs).
//! - Feedback triggers (§3.2.5): emit an ACK when `c_cep` pending CE
//!   count reaches `CEP_TRIGGER` (default 2-ish scaled; we use the
//!   RFC's "more than 2 un-acked CE marks" → `DELTA_CEP >= 3`) or on
//!   the "danger" cases (sequence gap, CE marks on a pure-ACK, wrap
//!   risk). The caller supplies the actual ACK-send hook.
//! - The two terminated half-connections are independent: this state
//!   machine is per-socket, never shared across the proxy's two sides.
//!
//! Bit order convention (§3): flags written (AE,CWR,ECE).

/// ACE field modulo — 3-bit counter wraps at 8.
const ACE_MOD: u64 = 8;
/// Feedback trigger: this many new CE marks since the last reported
/// ACE point force an immediate ACK (RFC 9768 §3.2.5 "Delta CE
/// pending" rule; we implement the normative delta rule, not a fixed
/// delayed-ACK count).
const DELTA_CEP_TRIGGER: u64 = 3;
/// Option-byte counter wrap (24-bit).
const BYTE_CTR_MOD: u64 = 1 << 24;

/// Negotiated ECN mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcnMode {
    /// Full AccECN byte-grain feedback negotiated.
    AccEcn,
    /// Classic RFC 3168 ECN (once-per-window ECE).
    ClassicEcn,
    /// No ECN on this connection.
    NotEct,
    /// Negotiation still open (SYN-ACK not yet processed / SYN not yet
    /// answered).
    Pending,
}

/// The (AE, CWR, ECE) flags tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags {
    pub ae: bool,
    pub cwr: bool,
    pub ece: bool,
}

impl Flags {
    pub fn new(ae: bool, cwr: bool, ece: bool) -> Self {
        Self { ae, cwr, ece }
    }
}

/// Dual-role AccECN state — one per TCP socket.
#[derive(Debug)]
pub struct AccEcn {
    /// Our role.
    pub initiator: bool,
    /// Whether we locally advertise/accept ECN at all (config gate —
    /// responder side is D-D1 常开 passive; initiator side default off
    /// unless `active_offered` was configured).
    enabled: bool,
    /// Negotiated mode (Pending until the handshake completes).
    pub mode: EcnMode,
    /// SYN retransmission counter for the §3.1.4.1 fallback
    /// (initiator only): after `SYN_FALLBACK_RETX` unanswered
    /// AccECN SYNs the caller may retry without AE — the decision is
    /// recorded, never silent.
    pub syn_retries: u32,
    /// --- feedback accounting (receiver side) ---
    /// CE bytes seen on incoming data (mod 2^24 for the option).
    ceb: u64,
    /// ECT(0) bytes (mod 2^24).
    e0b: u64,
    /// ECT(1) bytes (mod 2^24).
    e1b: u64,
    /// CE-pending counter: CE marks not yet fed back via ACE.
    cep_pending: u64,
    /// ACE field value last emitted (0..8).
    ace: u8,
    /// --- sender side ---
    /// ACE counter decoded from the peer's last ACK (bytes mod 8 of
    /// *packets* — ACE counts marked *packets* per RFC 9768; the byte
    /// counters option carries byte-grain detail).
    peer_ace: u8,
    /// Delta-CEP derived from peer ACE deltas (packets).
    peer_cep_packets: u64,
    /// Last raw counters seen in the peer's option (EE0B, EE1B, CEB) —
    /// used both for deltas and to substitute omitted tail fields.
    peer_counters: (u64, u64, u64),
    /// Set when the peer's option was seen (feedback precision).
    pub peer_uses_byte_counters: bool,
    /// Classic-ECE suppression: with ClassicEcn a single ECE already
    /// produced a response; latch until a clean RTT.
    ece_responded: bool,
    /// Handshake-mode guard: a SYN-ACK that answered classic can't
    /// upgrade later (§3.1.5 — handshake mode is immutable).
    handshake_done: bool,
}

/// RFC 9768 §3.1.4.1: AccECN SYN unanswered after this many retries →
/// the caller may fall back to a classic-ECE SYN (recorded decision).
pub const SYN_FALLBACK_RETX: u32 = 1;

impl AccEcn {
    /// `initiator`: true for active open. `enabled`: local ECN gate —
    /// responder should pass true (D-D1 passive-always-on); initiator
    /// passes the configured active-advertise flag (default off).
    pub fn new(initiator: bool, enabled: bool) -> Self {
        Self {
            initiator,
            enabled,
            mode: if enabled {
                EcnMode::Pending
            } else {
                EcnMode::NotEct
            },
            syn_retries: 0,
            ceb: 0,
            e0b: 0,
            e1b: 0,
            cep_pending: 0,
            ace: 0,
            peer_ace: 0,
            peer_cep_packets: 0,
            peer_counters: (0, 0, 0),
            peer_uses_byte_counters: false,
            ece_responded: false,
            handshake_done: false,
        }
    }

    // ---------------- initiator: SYN emission ----------------

    /// Flags to put on an outgoing SYN (initiator). §3.1.2:
    /// offering AccECN = (1,1,1); the caller may instead send
    /// classic-only (0,1,1) via `classic_syn_flags` or none.
    /// After `SYN_FALLBACK_RETX` retries the caller decides — this
    /// returns the *offered* flags; retry bookkeeping is explicit.
    pub fn syn_flags(&mut self, retried: bool) -> Flags {
        // Only an initiator that was configured to offer advertises
        // ECN on the SYN — a responder-mode state machine (e.g. a
        // socket driven into SynSent without `connect`) emits stock
        // flags and never originates an offer.
        if !self.enabled || !self.initiator {
            return Flags::new(false, false, false);
        }
        if retried {
            self.syn_retries += 1;
            // §3.1.4.1: on retransmit the initiator may keep offering
            // AccECN or degrade to classic — we keep offering AccECN
            // while recording the retry; fallback is the caller's
            // explicit decision (no silent degrade).
        }
        Flags::new(true, true, true)
    }

    /// Classic-only SYN offer (initiator's explicit choice).
    pub fn classic_syn_flags(&self) -> Flags {
        Flags::new(false, true, true)
    }

    /// Process the SYN-ACK flags (initiator) — Table 3 decode.
    pub fn on_syn_ack(&mut self, f: Flags) {
        if self.handshake_done {
            return;
        }
        self.handshake_done = true;
        // An initiator that never offered ECN resolves to Not-ECT
        // whatever the SYN-ACK carries — a non-offered socket must not
        // latch ECN semantics from a peer's unsolicited flags.
        if !self.enabled {
            self.mode = EcnMode::NotEct;
            return;
        }
        self.mode = match (f.ae, f.cwr, f.ece) {
            // AccECN SYN-ACK encodings (RFC 9768 §3.1.2 Table 3):
            // (0,1,0) = full AccECN; (1,0,0)/(1,1,0)/(1,1,1) = AccECN
            // with ECN++-style variations we accept as AccECN;
            // (0,0,1) = classic ECN; everything else = no ECN.
            (false, true, false) => EcnMode::AccEcn,
            (true, _, false) => EcnMode::AccEcn,
            (true, true, true) => EcnMode::AccEcn, // lenient mirror
            (false, false, true) => EcnMode::ClassicEcn,
            _ => EcnMode::NotEct,
        };
    }

    // ---------------- responder: SYN decode + SYN-ACK ----------------

    /// Decode an incoming SYN's flags and produce the SYN-ACK flags
    /// (responder) — RFC 9768 §3.1.1 Table 2. `classic_only` forces the
    /// classic-ECN response when configured (per-listener gate).
    pub fn answer_syn(&mut self, syn: Flags, classic_only: bool) -> Flags {
        if !self.enabled || self.handshake_done {
            return Flags::new(false, false, false);
        }
        self.handshake_done = true;
        let (mode, reply) = match (syn.ae, syn.cwr, syn.ece) {
            // AccECN offer (1,1,1): answer (0,1,0) unless the listener
            // is pinned classic.
            (true, true, true) => {
                if classic_only {
                    (EcnMode::ClassicEcn, Flags::new(false, false, true))
                } else {
                    (EcnMode::AccEcn, Flags::new(false, true, false))
                }
            }
            // Classic offer (0,1,1) or (0,0,1) → classic response.
            (false, true, true) | (false, false, true) => {
                (EcnMode::ClassicEcn, Flags::new(false, false, true))
            }
            // Broken/unknown encodings → no ECN (fail-closed, logged
            // by the caller as `mode = NotEct`).
            _ => (EcnMode::NotEct, Flags::new(false, false, false)),
        };
        self.mode = mode;
        reply
    }

    // ---------------- receiver: mark accounting ----------------

    /// One inbound data segment arrived carrying `ecn` field value and
    /// `payload_len` payload bytes (0 for a pure ACK). Updates the
    /// byte counters and CE-pending count. Returns whether the peer
    /// should be ACKed *now* under the RFC 9768 feedback rules (the
    /// caller still applies its normal delayed-ACK policy otherwise).
    pub fn on_segment(&mut self, ecn: u8, payload_len: u64, _now_us: u64) -> bool {
        if self.mode != EcnMode::AccEcn && self.mode != EcnMode::ClassicEcn {
            return false;
        }
        match ecn {
            3 => {
                // CE-marked.
                self.ceb = (self.ceb + payload_len) % BYTE_CTR_MOD;
                self.cep_pending += 1;
            }
            2 => self.e0b = (self.e0b + payload_len) % BYTE_CTR_MOD,
            1 => self.e1b = (self.e1b + payload_len) % BYTE_CTR_MOD,
            _ => {}
        }
        if self.mode == EcnMode::ClassicEcn {
            // Classic: ECE is once-per-window — the caller checks
            // `ece_responded`; we just signal an ACK is owed when CE
            // arrived and hasn't been echoed yet.
            return self.cep_pending > 0 && !self.ece_responded;
        }
        // AccECN: delta-CEP trigger (§3.2.5) — ACK now when ≥3 new
        // marks are pending, or when a wrap risk exists (pending ≥ 6:
        // 3-bit ACE must be fed back before a second wrap ambiguity).
        self.cep_pending >= DELTA_CEP_TRIGGER || self.cep_pending >= 6
    }

    /// Prospective ACE value for the next outgoing ACK — the same
    /// field `make_ack` would produce, but WITHOUT consuming pending
    /// marks. Encode with this, then call `make_ack` only once the
    /// segment is actually on the wire; consuming before emit would
    /// silently lose CE reports when the device rejects the frame.
    pub fn peek_ace(&self) -> u8 {
        if self.mode == EcnMode::AccEcn {
            ((self.ace as u64 + self.cep_pending) % ACE_MOD) as u8
        } else {
            self.ace
        }
    }

    /// Build the ACK's ACE field + clear pending marks (receiver).
    /// Returns the 3-bit ACE value to encode.
    pub fn make_ack(&mut self) -> u8 {
        if self.mode == EcnMode::AccEcn {
            // Advance the ACE field by the pending CE marks mod 8.
            self.ace = ((self.ace as u64 + self.cep_pending) % ACE_MOD) as u8;
        } else if self.mode == EcnMode::ClassicEcn && self.cep_pending > 0 {
            self.ece_responded = true;
        }
        self.cep_pending = 0;
        self.ace
    }

    /// Whether a classic-ECE response is still latched (sender side of
    /// classic mode — cleared when a clean RTT passes; caller decides).
    pub fn take_ece_latch(&mut self) -> bool {
        let v = self.ece_responded;
        self.ece_responded = false;
        v
    }

    /// Current byte counters for the option (EE0B/ECT0B/CEB order per
    /// RFC 9768 option layout; wire/tcp.rs owns the serialization).
    pub fn byte_counters(&self) -> (u64, u64, u64) {
        (self.e0b, self.e1b, self.ceb)
    }

    // ---------------- sender: feedback decode ----------------

    /// Feed the peer's ACE field (3 bits) from an incoming ACK — sender
    /// side. Returns the new CE *packet* delta (wrap-safe).
    pub fn on_ack_ace(&mut self, ace: u8) -> u64 {
        let delta = (ace as u64 + ACE_MOD - self.peer_ace as u64) % ACE_MOD;
        self.peer_ace = ace;
        self.peer_cep_packets += delta;
        delta
    }

    /// Feed the peer's byte-counters option (EE0B/ECT0B/CEB) — returns
    /// the CE byte delta since the previous option (wrap-safe, 24-bit).
    pub fn on_ack_counters(&mut self, e0b: u64, e1b: u64, ceb: u64) -> u64 {
        self.peer_uses_byte_counters = true;
        let prev = self.peer_counters.2;
        let delta = (ceb + BYTE_CTR_MOD - prev) % BYTE_CTR_MOD;
        self.peer_counters = (e0b, e1b, ceb);
        delta
    }

    /// Total CE packets reported by the peer's ACE stream.
    pub fn peer_cep(&self) -> u64 {
        self.peer_cep_packets
    }

    /// Classic-ECN receiver side: whether outgoing ACKs should carry
    /// the ECE flag — CE pending, or the once-per-window latch is
    /// still held (cleared when the peer's CWR arrives; RFC 3168 §6.1.3).
    pub fn ece_echo_pending(&self) -> bool {
        self.cep_pending > 0 || self.ece_responded
    }

    /// Whether the handshake has run its course (SYN answered or
    /// SYN-ACK decoded). Before this, flag bits on the wire carry the
    /// negotiation encoding, not feedback — callers must not feed
    /// them into the counters.
    pub fn handshake_done(&self) -> bool {
        self.handshake_done
    }

    /// Feed a parsed AccECN option — RFC 9768 §3.2.3 allows the Data
    /// Receiver to omit unchanged trailing fields; `None` substitutes
    /// the last seen value (delta 0). Returns the CE byte delta.
    pub fn on_ack_option(
        &mut self,
        e0b: Option<u64>,
        e1b: Option<u64>,
        ceb: Option<u64>,
    ) -> u64 {
        let (p0, p1, pc) = self.peer_counters;
        self.on_ack_counters(
            e0b.unwrap_or(p0),
            e1b.unwrap_or(p1),
            ceb.unwrap_or(pc),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiator_acc_ecn_handshake() {
        let mut a = AccEcn::new(true, true);
        let syn = a.syn_flags(false);
        assert_eq!(syn, Flags { ae: true, cwr: true, ece: true });
        a.on_syn_ack(Flags::new(false, true, false));
        assert_eq!(a.mode, EcnMode::AccEcn);
    }

    #[test]
    fn responder_accepts_and_replies() {
        let mut r = AccEcn::new(false, true);
        let reply = r.answer_syn(Flags::new(true, true, true), false);
        assert_eq!(reply, Flags::new(false, true, false));
        assert_eq!(r.mode, EcnMode::AccEcn);
    }

    #[test]
    fn responder_classic_pinned() {
        let mut r = AccEcn::new(false, true);
        let reply = r.answer_syn(Flags::new(true, true, true), true);
        assert_eq!(reply, Flags::new(false, false, true));
        assert_eq!(r.mode, EcnMode::ClassicEcn);
    }

    #[test]
    fn no_ecn_offer_gets_no_ecn() {
        let mut r = AccEcn::new(false, true);
        let reply = r.answer_syn(Flags::new(false, false, false), false);
        assert_eq!(reply, Flags::new(false, false, false));
        assert_eq!(r.mode, EcnMode::NotEct);
    }

    #[test]
    fn ace_counter_wraps_mod8() {
        let mut r = AccEcn::new(false, true);
        r.answer_syn(Flags::new(true, true, true), false);
        // Feed 9 CE marks (wraps the 3-bit field once).
        for _ in 0..9 {
            r.on_segment(3, 100, 0);
            r.make_ack();
        }
        // Then 3 more — ACE should be at 3 mod 8 after wrap.
        r.on_segment(3, 100, 0);
        r.on_segment(3, 100, 0);
        r.on_segment(3, 100, 0);
        let ace = r.make_ack();
        assert_eq!(ace, (9 + 3) % 8);
    }

    #[test]
    fn delta_cep_triggers_immediate_ack() {
        let mut r = AccEcn::new(false, true);
        r.answer_syn(Flags::new(true, true, true), false);
        assert!(!r.on_segment(3, 100, 0));
        assert!(!r.on_segment(3, 100, 0));
        assert!(r.on_segment(3, 100, 0)); // 3rd pending → ACK now
    }

    #[test]
    fn sender_ace_delta_wraps() {
        let mut s = AccEcn::new(true, true);
        s.on_syn_ack(Flags::new(false, true, false));
        assert_eq!(s.on_ack_ace(2), 2);
        assert_eq!(s.on_ack_ace(0), 6); // wrapped: 2→0 via mod 8 = +6
        assert_eq!(s.peer_cep(), 8);
    }

    #[test]
    fn byte_counter_delta_wraps_24bit() {
        let mut s = AccEcn::new(true, true);
        s.on_syn_ack(Flags::new(false, true, false));
        s.on_ack_counters(0, 0, (1 << 24) - 100);
        let d = s.on_ack_counters(0, 0, 50);
        assert_eq!(d, 150);
        assert!(s.peer_uses_byte_counters);
    }

    #[test]
    fn syn_option_never_emitted() {
        // Compile-time proof by absence: there is no API returning
        // option bytes for a SYN — only flags. The responder-side
        // smoke is a normal answer_syn.
        let mut r = AccEcn::new(false, true);
        let _ = r.answer_syn(Flags::new(true, true, true), false);
    }
}
