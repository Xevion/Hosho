use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_xml_rs::from_str;
use std::collections::HashMap;
use std::sync::Arc;
use strum_macros::Display;
use tokio::sync::{Mutex, mpsc};
use win_event_log::prelude::{Condition, EventFilter, Query, QueryItem, QueryList, WinEvents};

use crate::errors::SentinelError;

use super::EventDetails;
use super::{Event, EventListener};

#[derive(Debug, Clone)]
pub struct LogonEvent {
    pub username: String,
    pub source_ip: String,
    pub variant: LogonVariant,
    #[allow(dead_code)]
    pub event_record_id: u32,
}

pub fn parse_login_event(xml: &str) -> anyhow::Result<(DateTime<Utc>, LogonEvent)> {
    #[derive(Debug, Deserialize)]
    struct SecurityEvent {
        #[serde(rename = "System")]
        system: System,
        #[serde(rename = "EventData")]
        event_data: EventData,
    }

    #[derive(Debug, Deserialize)]
    struct System {
        #[serde(rename = "TimeCreated")]
        time_created: TimeCreated,
        #[serde(rename = "EventRecordID")]
        event_record_id: u32,
    }

    #[derive(Debug, Deserialize)]
    struct TimeCreated {
        #[serde(rename = "@SystemTime")]
        system_time: String,
    }

    #[derive(Debug, Deserialize)]
    struct EventData {
        #[serde(rename = "#content")]
        data: Vec<DataField>,
    }

    #[derive(Debug, Deserialize)]
    struct DataField {
        #[serde(rename = "@Name")]
        name: String,
        #[serde(rename = "#text")]
        value: String,
    }

    let event: SecurityEvent =
        from_str(xml).map_err(|e| SentinelError::XmlParseError(e.to_string()))?;

    let timestamp_str = &event.system.time_created.system_time;
    let timestamp: DateTime<Utc> = DateTime::parse_from_rfc3339(timestamp_str)
        .map_err(|e| SentinelError::TimestampParseError(e.to_string()))?
        .with_timezone(&Utc);

    let mut data_fields = HashMap::<String, String>::new();

    for data_field in &event.event_data.data {
        if let "TargetUserName" | "TargetDomainName" | "IpAddress" | "LogonType" =
            data_field.name.as_str()
        {
            data_fields.insert(data_field.name.clone(), data_field.value.clone());
        }
    }

    let username = if let (Some(user), Some(domain)) = (
        data_fields.get("TargetUserName"),
        data_fields.get("TargetDomainName"),
    ) {
        Some(if domain.is_empty() || domain == "-" {
            user.clone()
        } else {
            format!("{}@{}", user, domain)
        })
    } else {
        None
    }
    .ok_or(SentinelError::XmlParseError(
        "Username not found".to_string(),
    ))?;

    let source_ip = data_fields
        .get("IpAddress")
        .ok_or(SentinelError::XmlParseError(
            "IpAddress not found".to_string(),
        ))?
        .clone();

    let variant = LogonVariant::from_string(data_fields.get("LogonType").ok_or(
        SentinelError::XmlParseError("Logon type not found".to_string()),
    )?);

    Ok((
        timestamp,
        LogonEvent {
            username,
            source_ip,
            variant,
            event_record_id: event.system.event_record_id,
        },
    ))
}

pub struct LogonListener {
    tx: Arc<Mutex<mpsc::Sender<Event>>>,
}

impl Clone for LogonListener {
    fn clone(&self) -> Self {
        Self {
            tx: Arc::clone(&self.tx),
        }
    }
}

impl LogonListener {
    pub fn new(tx: mpsc::Sender<Event>) -> Self {
        Self {
            tx: Arc::new(Mutex::new(tx)),
        }
    }

    fn get_query() -> QueryList {
        QueryList::new()
            .with_query(
                Query::new()
                    .item(
                        QueryItem::selector("Security".to_owned())
                            .system_conditions(Condition::or(vec![Condition::filter(
                                EventFilter::event(4625),
                            )]))
                            .build(),
                    )
                    .query(),
            )
            .build()
    }

    fn query_events() -> anyhow::Result<Vec<Event>> {
        let events = {
            let query = Self::get_query();
            WinEvents::get(query).map_err(|e| {
                SentinelError::EventQueryError(format!("Failed to query Security events: {}", e))
            })?
        };
        let mut parsed_events = Vec::new();
        for event in events {
            let event_xml = event.to_string();
            match parse_login_event(&event_xml) {
                Ok((timestamp, login_event)) => {
                    parsed_events.push(Event {
                        details: EventDetails::Login(login_event),
                        timestamp,
                    });
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(parsed_events)
    }
}

impl EventListener for LogonListener {
    fn invoke(&self) {
        let tx_clone = Arc::clone(&self.tx);

        tokio::spawn(async move {
            let processing_task = tokio::task::spawn_blocking(Self::query_events);

            match processing_task.await {
                Ok(Ok(events)) => {
                    for event in events {
                        if tx_clone.lock().await.send(event).await.is_err() {
                            eprintln!(
                                "Failed to send event to channel, receiver dropped: {}",
                                SentinelError::ChannelSendError
                            );
                            break;
                        }
                    }
                }
                Ok(Err(e)) => {
                    eprintln!("Error processing security events: {}", e);
                }
                Err(e) => {
                    eprintln!("Processing task failed: {}", e);
                }
            }
        });
    }
}

#[derive(Debug, Clone, Display)]
pub enum LogonVariant {
    Interactive,
    Network,
    Batch,
    Service,
    Unlock,
    NetworkCleartext,
    NewCredentials,
    RemoteInteractive,
    CachedInteractive,
    CachedRemoteInteractive,
    CachedUnlock,
    Unknown(isize),
    Invalid(String),
}

impl LogonVariant {
    pub fn from_string(s: &str) -> Self {
        match s.parse::<isize>() {
            Ok(num) => match num {
                2 => LogonVariant::Interactive,
                3 => LogonVariant::Network,
                4 => LogonVariant::Batch,
                5 => LogonVariant::Service,
                7 => LogonVariant::Unlock,
                8 => LogonVariant::NetworkCleartext,
                9 => LogonVariant::NewCredentials,
                10 => LogonVariant::RemoteInteractive,
                11 => LogonVariant::CachedInteractive,
                12 => LogonVariant::CachedRemoteInteractive,
                13 => LogonVariant::CachedUnlock,
                _ => LogonVariant::Unknown(num),
            },
            Err(_) => LogonVariant::Invalid(s.to_string()),
        }
    }
}
