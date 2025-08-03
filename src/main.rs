mod listener;

use crate::listener::{EventDetails, EventListener, LogonListener};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut logon_listener = LogonListener::new();

    let mut listeners: Vec<Box<dyn EventListener>> = vec![Box::new(logon_listener)];

    let mut event_channels = Vec::new();

    for listener in &mut listeners {
        match listener.get_events() {
            Ok(rx) => event_channels.push(rx),
            Err(e) => eprintln!("Error initializing listener: {}", e),
        }
    }

    let mut handles = Vec::new();

    for mut rx in event_channels {
        let handle = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
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
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await?;
    }

    Ok(())
}
