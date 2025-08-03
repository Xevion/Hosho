pub mod logon;

use chrono::{DateTime, Utc};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct Event {
    pub details: EventDetails,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum EventDetails {
    Login(LogonEvent),
}

pub trait EventListener {
    fn get_events(&mut self) -> Result<mpsc::Receiver<Event>, Box<dyn std::error::Error>>;
}

pub use logon::{LogonEvent, LogonListener, LogonVariant};
