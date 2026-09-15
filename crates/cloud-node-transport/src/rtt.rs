use std::time::Duration;

/// RFC 6298 RTT estimator plus a running minimum.
///
/// Controllers consult this for srtt-derived pacing (Reno/Cubic pacing =
/// cwnd/srtt) and BBR-style min_rtt windows. `sample` is fed only with
/// non-retransmitted RTT observations — Karn's rule is enforced upstream
/// by [`crate::rate_sample`].
#[derive(Clone, Copy, Debug, Default)]
pub struct RttState {
    /// RFC 6298 SRTT (alpha = 1/8).
    pub srtt: Option<Duration>,
    /// RFC 6298 RTTVAR (beta = 1/4).
    pub rttvar: Option<Duration>,
    /// Smallest RTT ever observed — BBR min_rtt window feeds this later.
    pub min_rtt: Option<Duration>,
    /// Number of samples taken.
    pub samples: u64,
}

impl RttState {
    /// RFC 6298 lower RTO bound (Linux uses 200ms).
    pub const RTO_MIN: Duration = Duration::from_millis(200);
    /// RFC 6298 upper RTO bound.
    pub const RTO_MAX: Duration = Duration::from_secs(60);

    pub fn new() -> Self {
        Self::default()
    }

    pub fn sample(&mut self, rtt: Duration) {
        self.samples += 1;
        self.min_rtt = Some(self.min_rtt.map_or(rtt, |m| m.min(rtt)));
        match (self.srtt, self.rttvar) {
            (None, _) => {
                self.srtt = Some(rtt);
                self.rttvar = Some(rtt / 2);
            }
            (Some(srtt), Some(rttvar)) => {
                let diff = srtt.abs_diff(rtt);
                let rttvar = (rttvar * 3 + diff) / 4;
                self.rttvar = Some(rttvar);
                self.srtt = Some((srtt * 7 + rtt) / 8);
            }
            (Some(_), None) => unreachable!("srtt implies rttvar"),
        }
    }

    /// RFC 6298 RTO = srtt + max(G, K*rttvar), clamped.
    pub fn rto(&self) -> Duration {
        let base = self
            .srtt
            .map(|s| s + self.rttvar.unwrap_or_default() * 4)
            .unwrap_or(Duration::from_secs(1));
        base.clamp(Self::RTO_MIN, Self::RTO_MAX)
    }
}
