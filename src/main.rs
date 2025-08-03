mod errors;
mod listener;

use tokio::{select, sync::mpsc};

use crate::listener::{EventDetails, EventListener, LogonListener};

// Helper function to create select! branches for multiple receivers
macro_rules! select_all {
    ([$($receiver:expr),*], $handler:ident) => {
        select! {
            $(
                Some(event) = $receiver.recv() => {
                    $handler(event);
                }
            )*
        }
    };
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (logon_tx, mut logon_rx) = mpsc::channel(100);
    let (logon_tx2, mut logon_rx2) = mpsc::channel(100);
    let listeners = vec![LogonListener::new(logon_tx), LogonListener::new(logon_tx2)];

    for listener in listeners {
        let listener_clone = listener.clone();
        tokio::spawn(async move {
            loop {
                listener_clone.invoke();
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    let handle_event = |event: crate::listener::Event| match event.details {
        EventDetails::Login(login_event) => {
            println!(
                r#"Event: Failed Login for {} ({}) on {} from {}"#,
                login_event.username,
                login_event.variant,
                event
                    .timestamp
                    .with_timezone(&chrono::Local)
                    .format("%A, %B %d, %Y at %I:%M:%S %p"),
                login_event.source_ip
            );
        }
    };

    loop {
        select_all! {
            [&mut logon_rx, &mut logon_rx2],
            handle_event
        };
    }
}
