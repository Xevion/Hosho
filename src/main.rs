mod listener;

use tokio::{select, sync::mpsc};

use crate::listener::{EventDetails, EventListener, LogonListener};

fn handle_event(listener_name: &str, event: crate::listener::Event) {
    match event.details {
        EventDetails::Login(login_event) => {
            println!(
                r#"{} Event: Failed Login for {} ({}) on {} from {}"#,
                listener_name,
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

// Helper function to create select! branches for multiple receivers
macro_rules! create_select_branches {
    ($($name:expr, $receiver:expr),* $(,)?) => {
        select! {
            $(
                Some(event) = $receiver.recv() => {
                    handle_event($name, event);
                }
            )*
        }
    };
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (logon_tx, mut logon_rx) = mpsc::channel(100);
    let listeners = vec![LogonListener::new(logon_tx)];

    for listener in listeners {
        let listener_clone = listener.clone();
        tokio::spawn(async move {
            loop {
                listener_clone.invoke();
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    loop {
        create_select_branches!("Logon", &mut logon_rx,);
    }
}
