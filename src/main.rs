mod listener;
use listener::{EventListener, LogonListener};

use crate::listener::EventDetails;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut listener = LogonListener::new();
    match listener.get_events() {
        Ok(events) => {
            for event in events {
                match event.details {
                    EventDetails::Login(login_event) => {
                        println!(
                            r#"Failed Login Event for {} ({}) on {} from {}"#,
                            login_event.username,
                            login_event.variant,
                            event
                                .timestamp
                                .with_timezone(&chrono::Local)
                                .format("%A, %B %d, %Y at %I:%M:%S %p"),
                            login_event.source_ip
                        );
                    }
                    _ => {
                        println!("Other event detected: {:?}", event.details);
                    }
                }
            }
            return Ok(());
        }
        Err(e) => {
            eprintln!("Error querying event log: {}", e);
            return Err(e);
        }
    }
}
