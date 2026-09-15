use std::time::Duration;

/// Monotonic microsecond instant shared by all transport machinery.
///
/// The crate deliberately carries a plain integer rather than a clock:
/// the dataplane feeds it from `TransportClock` (src/transport_clock.rs),
/// the simulator feeds it from its virtual time. Both are monotonic µs —
/// this type only provides the arithmetic and ordering.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransportInstant(u64);

impl TransportInstant {
    pub const ZERO: Self = Self(0);

    pub const fn from_micros(us: u64) -> Self {
        Self(us)
    }

    pub fn from_duration(d: Duration) -> Self {
        Self(d.as_micros() as u64)
    }

    pub const fn micros(self) -> u64 {
        self.0
    }

    pub fn duration_since(self, earlier: TransportInstant) -> Duration {
        Duration::from_micros(self.0.saturating_sub(earlier.0))
    }

    pub fn checked_add(self, d: Duration) -> Option<Self> {
        self.0.checked_add(d.as_micros() as u64).map(Self)
    }

    pub fn saturating_add(self, d: Duration) -> Self {
        Self(self.0.saturating_add(d.as_micros() as u64))
    }
}

impl std::fmt::Debug for TransportInstant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}us", self.0)
    }
}

impl std::fmt::Display for TransportInstant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::ops::Add<Duration> for TransportInstant {
    type Output = TransportInstant;
    fn add(self, rhs: Duration) -> TransportInstant {
        self.saturating_add(rhs)
    }
}

impl std::ops::Sub<TransportInstant> for TransportInstant {
    type Output = Duration;
    fn sub(self, rhs: TransportInstant) -> Duration {
        self.duration_since(rhs)
    }
}
