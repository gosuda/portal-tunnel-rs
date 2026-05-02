// INVARIANT: a port released within `grace` is sticky to its owner; alloc returns None if the pool is exhausted.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub(super) struct PortAllocator {
    available: VecDeque<u16>,
    in_use: HashMap<u16, String>,
    reserved: HashMap<String, PortReservation>,
    grace: Duration,
}

#[derive(Clone, Copy)]
struct PortReservation {
    port: u16,
    expires_at: Instant,
}

impl PortAllocator {
    pub(super) fn new(min_port: u16, max_port: u16, grace: Duration) -> Self {
        let available = if min_port > 0 && max_port >= min_port {
            (min_port..=max_port).collect()
        } else {
            VecDeque::new()
        };
        Self {
            available,
            in_use: HashMap::new(),
            reserved: HashMap::new(),
            grace,
        }
    }

    pub(super) fn allocate(&mut self, owner: &str) -> Option<u16> {
        self.cleanup_expired(Instant::now());
        if let Some(reservation) = self.reserved.remove(owner) {
            self.in_use.insert(reservation.port, owner.to_string());
            return Some(reservation.port);
        }
        let port = self.available.pop_front()?;
        self.in_use.insert(port, owner.to_string());
        Some(port)
    }

    pub(super) fn release(&mut self, port: u16) {
        let Some(owner) = self.in_use.remove(&port) else {
            return;
        };
        if let Some(previous) = self.reserved.insert(
            owner,
            PortReservation {
                port,
                expires_at: Instant::now() + self.grace,
            },
        ) {
            self.sorted_insert(previous.port);
        }
        self.cleanup_expired(Instant::now());
    }

    fn cleanup_expired(&mut self, now: Instant) {
        let expired: Vec<String> = self
            .reserved
            .iter()
            .filter_map(|(owner, reservation)| {
                (now > reservation.expires_at).then_some(owner.clone())
            })
            .collect();
        for owner in expired {
            if let Some(reservation) = self.reserved.remove(&owner) {
                self.sorted_insert(reservation.port);
            }
        }
    }

    fn sorted_insert(&mut self, port: u16) {
        let idx = self
            .available
            .iter()
            .position(|candidate| *candidate >= port)
            .unwrap_or(self.available.len());
        self.available.insert(idx, port);
    }
}
