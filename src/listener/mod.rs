pub mod logon;

use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct Event {
    pub details: EventDetails,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum EventDetails {
    Login(LogonEvent),
}

pub trait EventListener: Clone {
    fn invoke(&self);
}

pub use logon::{LogonEvent, LogonListener};
