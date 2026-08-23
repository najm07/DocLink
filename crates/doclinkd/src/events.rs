//! Daemon-side notification events, consumed by the window shell's
//! toast poller (`GET /v1/admin/events?since=<id>`).
//!
//! A tiny monotonic-id ring buffer: producers (pairing handler, expiry
//! sweeper) append; the consumer fetches everything newer than the last
//! id it showed. In-memory only — after a daemon restart the window
//! re-baselines silently instead of replaying stale history.

use serde::Serialize;
use std::collections::{HashSet, VecDeque};

/// Ring capacity: far more than any human accumulates between polls,
/// small enough that a forgotten window costs nothing.
const CAP: usize = 100;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Event {
    pub id: u64,
    /// "pair-request" | "grant-expiring"
    pub kind: String,
    pub title: String,
    pub body: String,
    pub unix: u64,
}

#[derive(Default)]
pub struct Events {
    next_id: u64,
    items: VecDeque<Event>,
    /// (fingerprint, expires_unix) pairs already announced, so the
    /// 60 s sweeper announces each approaching expiry exactly once.
    expiry_announced: HashSet<(String, u64)>,
}

impl Events {
    pub fn push(&mut self, kind: &str, title: String, body: String) -> Event {
        let id = self.next_id + 1;
        self.next_id = id;
        let ev = Event {
            id,
            kind: kind.to_string(),
            title,
            body,
            unix: unix_now(),
        };
        self.items.push_back(ev.clone());
        while self.items.len() > CAP {
            self.items.pop_front();
        }
        ev
    }

    /// All events with id > `since`, oldest first.
    pub fn since(&self, since: u64) -> Vec<Event> {
        self.items.iter().filter(|e| e.id > since).cloned().collect()
    }

    /// True the first time this (fingerprint, expiry) pair is asked about.
    pub fn claim_expiry(&mut self, fingerprint: &str, expires_unix: u64) -> bool {
        self.expiry_announced
            .insert((fingerprint.to_string(), expires_unix))
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub type SharedEvents = std::sync::Arc<std::sync::Mutex<Events>>;

pub fn shared() -> SharedEvents {
    std::sync::Arc::new(std::sync::Mutex::new(Events::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_monotonic_and_since_filters() {
        let mut e = Events::default();
        let a = e.push("pair-request", "t1".into(), "b1".into());
        let b = e.push("grant-expiring", "t2".into(), "b2".into());
        assert_eq!((a.id, b.id), (1, 2));
        let all = e.since(0);
        assert_eq!(all.len(), 2);
        assert_eq!(e.since(a.id), vec![b.clone()]);
        assert!(e.since(b.id).is_empty());
    }

    #[test]
    fn ring_buffer_caps_at_capacity() {
        let mut e = Events::default();
        for i in 0..(CAP as u64 + 25) {
            e.push("pair-request", format!("t{i}"), String::new());
        }
        assert_eq!(e.items.len(), CAP);
        // Oldest ids are gone; the newest survive.
        let newest = e.since(CAP as u64);
        assert_eq!(newest.len(), 25);
        assert_eq!(newest.last().unwrap().title, "t124");
    }

    #[test]
    fn expiry_claim_is_once_per_pair() {
        let mut e = Events::default();
        assert!(e.claim_expiry("fp", 100));
        assert!(!e.claim_expiry("fp", 100));
        assert!(e.claim_expiry("fp", 200)); // renewed grant -> announce again
        assert!(e.claim_expiry("other", 100));
    }
}
