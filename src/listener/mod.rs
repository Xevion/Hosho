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
    Wake(WakeEvent),
    Activity(ActivityEvent),
}

#[derive(Debug, Clone)]
pub enum ActivityType {
    Mouse,
    Keyboard,
    Device,
}

#[derive(Debug, Clone)]
pub struct ActivityEvent {
    pub activity_type: ActivityType,
}

#[derive(Debug, Clone)]
pub struct WakeEvent {}

pub trait EventListener {
    fn get_events(&mut self) -> Result<Vec<Event>, Box<dyn std::error::Error>>;
}

pub use logon::{LogonEvent, LogonExtractor, LogonVariant};
