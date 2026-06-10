use std::sync::LazyLock as Lazy;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub static CPU_TRANSFORM_GATE: Lazy<AdaptiveCpuGate> = Lazy::new(AdaptiveCpuGate::new);

pub struct AdaptiveCpuGate {
    in_flight: AtomicUsize,
    reservations: AtomicUsize,
    base_limit: usize,
}

pub struct CpuTransformReservation<'a> {
    gate: &'a AdaptiveCpuGate,
}

pub struct CpuTransformPermit<'a> {
    gate: &'a AdaptiveCpuGate,
}

impl AdaptiveCpuGate {
    pub fn new() -> Self {
        Self::with_base_limit(num_cpus::get().clamp(1, 8))
    }

    pub fn try_admit_optional(&self) -> Option<CpuTransformPermit<'_>> {
        self.try_admit()
    }

    pub fn try_reserve_optional(&self) -> Option<CpuTransformReservation<'_>> {
        let current = self.reservations.fetch_add(1, Ordering::AcqRel) + 1;
        if current <= self.dynamic_limit() {
            Some(CpuTransformReservation { gate: self })
        } else {
            self.reservations.fetch_sub(1, Ordering::AcqRel);
            None
        }
    }

    pub async fn acquire_required(&self, timeout: Duration) -> Option<CpuTransformPermit<'_>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(permit) = self.try_admit() {
                return Some(permit);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    pub fn acquire_required_blocking(&self, timeout: Duration) -> Option<CpuTransformPermit<'_>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(permit) = self.try_admit() {
                return Some(permit);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn dynamic_limit(&self) -> usize {
        limit_for_pressure(self.base_limit, crate::metrics::METRICS.get_node_pressure())
    }

    fn with_base_limit(base_limit: usize) -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            reservations: AtomicUsize::new(0),
            base_limit: base_limit.max(1),
        }
    }

    fn try_admit(&self) -> Option<CpuTransformPermit<'_>> {
        let current = self.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
        if current <= self.dynamic_limit() {
            Some(CpuTransformPermit { gate: self })
        } else {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            None
        }
    }
}

impl Default for AdaptiveCpuGate {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuTransformReservation<'_> {
    pub fn activate(&self) -> CpuTransformPermit<'_> {
        self.gate.in_flight.fetch_add(1, Ordering::AcqRel);
        CpuTransformPermit { gate: self.gate }
    }
}

impl Drop for CpuTransformReservation<'_> {
    fn drop(&mut self) {
        self.gate.reservations.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for CpuTransformPermit<'_> {
    fn drop(&mut self) {
        self.gate.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

fn limit_for_pressure(base: usize, pressure: f64) -> usize {
    let base = base.max(1);
    let pressure = if pressure.is_finite() { pressure } else { 0.0 };
    if pressure < 0.50 {
        base
    } else if pressure < 0.70 {
        (base * 3 / 4).max(1)
    } else if pressure < 0.85 {
        (base / 2).max(1)
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pressure_reduces_dynamic_limit() {
        assert_eq!(limit_for_pressure(8, 0.10), 8);
        assert_eq!(limit_for_pressure(8, 0.60), 6);
        assert_eq!(limit_for_pressure(8, 0.80), 4);
        assert_eq!(limit_for_pressure(8, 0.95), 1);
    }

    #[test]
    fn admission_rolls_back_when_limit_is_full() {
        let gate = AdaptiveCpuGate::with_base_limit(2);
        let first = gate.try_admit_optional().unwrap();
        let second = gate.try_admit_optional().unwrap();
        assert!(gate.try_admit_optional().is_none());
        assert_eq!(gate.in_flight.load(Ordering::Acquire), 2);
        drop(first);
        assert!(gate.try_admit_optional().is_some());
        drop(second);
    }

    #[test]
    fn reservations_do_not_count_as_running_transforms() {
        let gate = AdaptiveCpuGate::with_base_limit(1);
        let reservation = gate.try_reserve_optional().unwrap();
        assert_eq!(gate.reservations.load(Ordering::Acquire), 1);
        assert_eq!(gate.in_flight.load(Ordering::Acquire), 0);
        let permit = reservation.activate();
        assert_eq!(gate.in_flight.load(Ordering::Acquire), 1);
        drop(permit);
        drop(reservation);
        assert_eq!(gate.reservations.load(Ordering::Acquire), 0);
    }
}
