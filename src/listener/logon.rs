use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_xml_rs::from_str;
use win_event_log::prelude::{Condition, EventFilter, Query, QueryItem, QueryList, WinEvents};

use crate::EventDetails;

use super::{Event, EventListener};

#[derive(Debug, Clone)]
pub struct LogonEvent {
    pub username: String,
    pub source_ip: String,
    pub variant: LogonVariant,
    pub event_record_id: u32,
}

pub struct LogonExtractor;

impl LogonExtractor {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_login_event(
        &self,
        xml: &str,
    ) -> Result<(DateTime<Utc>, LogonEvent), Box<dyn std::error::Error>> {
        // Structs for parsing the Windows Security event XML
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
            from_str(xml).map_err(|e| format!("Failed to parse XML: {}", e))?;

        let timestamp_str = &event.system.time_created.system_time;
        let timestamp: DateTime<Utc> = DateTime::parse_from_rfc3339(timestamp_str)
            .map_err(|e| format!("Failed to parse timestamp: {}", e))?
            .with_timezone(&Utc);

        let mut target_username = None;
        let mut target_domain = None;
        let mut logon_type = None;
        let mut ip_address = None;

        for data_field in &event.event_data.data {
            match data_field.name.as_str() {
                "TargetUserName" => target_username = Some(data_field.value.clone()),
                "TargetDomainName" => target_domain = Some(data_field.value.clone()),
                "LogonType" => logon_type = Some(data_field.value.clone()),
                "IpAddress" => ip_address = Some(data_field.value.clone()),
                _ => {}
            }
        }

        let username = if let (Some(user), Some(domain)) = (&target_username, &target_domain) {
            if domain.is_empty() || domain == "-" {
                user.clone()
            } else {
                format!("{}@{}", user, domain)
            }
        } else {
            target_username.unwrap_or_else(|| "Unknown".to_string())
        };

        let source_ip = ip_address.unwrap_or_else(|| "N/A".to_string());

        let variant = if let Some(logon_type_str) = &logon_type {
            LogonVariant::from_string(logon_type_str)
        } else {
            LogonVariant::Invalid("N/A".to_string())
        };

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

    fn query_security_events(&self) -> Result<WinEvents, Box<dyn std::error::Error>> {
        let query = QueryList::new()
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
            .build();

        WinEvents::get(query).map_err(|e| format!("Failed to query Security events: {}", e).into())
    }
}

impl EventListener for LogonExtractor {
    fn get_events(&mut self) -> Result<Vec<Event>, Box<dyn std::error::Error>> {
        let events = self.query_security_events()?;
        let mut login_events = Vec::new();

        for event in events {
            let event_xml = event.to_string();

            match self.parse_login_event(&event_xml) {
                Ok((timestamp, login_event)) => {
                    login_events.push(Event {
                        details: EventDetails::Login(login_event),
                        timestamp,
                    });
                }
                Err(e) => {
                    eprintln!("Failed to parse login event: {}", e);
                }
            }
        }

        Ok(login_events)
    }
}

#[derive(Debug, Clone)]
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

    pub fn as_number(&self) -> isize {
        match self {
            LogonVariant::Interactive => 2,
            LogonVariant::Network => 3,
            LogonVariant::Batch => 4,
            LogonVariant::Service => 5,
            LogonVariant::Unlock => 7,
            LogonVariant::NetworkCleartext => 8,
            LogonVariant::NewCredentials => 9,
            LogonVariant::RemoteInteractive => 10,
            LogonVariant::CachedInteractive => 11,
            LogonVariant::CachedRemoteInteractive => 12,
            LogonVariant::CachedUnlock => 13,
            LogonVariant::Unknown(num) => *num,
            LogonVariant::Invalid(_) => -1,
        }
    }

    pub fn is_valid(&self) -> bool {
        !matches!(self, LogonVariant::Invalid(_))
    }
}

impl std::fmt::Display for LogonVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogonVariant::Interactive => write!(f, "Interactive"),
            LogonVariant::Network => write!(f, "Network"),
            LogonVariant::Batch => write!(f, "Batch"),
            LogonVariant::Service => write!(f, "Service"),
            LogonVariant::Unlock => write!(f, "Unlock"),
            LogonVariant::NetworkCleartext => write!(f, "Network Cleartext"),
            LogonVariant::NewCredentials => write!(f, "New Credentials"),
            LogonVariant::RemoteInteractive => write!(f, "Remote Interactive"),
            LogonVariant::CachedInteractive => write!(f, "Cached Interactive"),
            LogonVariant::CachedRemoteInteractive => write!(f, "Cached Remote Interactive"),
            LogonVariant::CachedUnlock => write!(f, "Cached Unlock"),
            LogonVariant::Unknown(num) => write!(f, "Unknown ({})", num),
            LogonVariant::Invalid(s) => write!(f, "Invalid ({})", s),
        }
    }
}

impl Default for LogonExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    #[test]
    fn test_parse_login_event() {
        let xml = r#"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4624</EventID>
        <Version>2</Version>
        <Level>0</Level>
        <Task>12544</Task>
        <Opcode>0</Opcode>
        <Keywords>0x8020000000000000</Keywords>
        <TimeCreated SystemTime='2025-07-22T16:25:08.8954670Z'/>
        <EventRecordID>8485950</EventRecordID>
        <Correlation ActivityID='{796f9c54-f28b-000e-ad9c-6f798bf2db01}'/>
        <Execution ProcessID='1404' ThreadID='41296'/>
        <Channel>Security</Channel>
        <Computer>Ether</Computer>
        <Security/>
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-5-18</Data>
        <Data Name='SubjectUserName'>ETHER$</Data>
        <Data Name='SubjectDomainName'>WORKGROUP</Data>
        <Data Name='SubjectLogonId'>0x3e7</Data>
        <Data Name='TargetUserSid'>S-1-5-18</Data>
        <Data Name='TargetUserName'>SYSTEM</Data>
        <Data Name='TargetDomainName'>NT AUTHORITY</Data>
        <Data Name='TargetLogonId'>0x3e7</Data>
        <Data Name='LogonType'>5</Data>
        <Data Name='LogonProcessName'>Advapi  </Data>
        <Data Name='AuthenticationPackageName'>Negotiate</Data>
        <Data Name='WorkstationName'>-</Data>
        <Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data>
        <Data Name='TransmittedServices'>-</Data>
        <Data Name='LmPackageName'>-</Data>
        <Data Name='KeyLength'>0</Data>
        <Data Name='ProcessId'>0x560</Data>
        <Data Name='ProcessName'>C:\Windows\System32\services.exe</Data>
        <Data Name='IpAddress'>-</Data>
        <Data Name='IpPort'>-</Data>
        <Data Name='ImpersonationLevel'>%%1833</Data>
        <Data Name='RestrictedAdminMode'>-</Data>
        <Data Name='TargetOutboundUserName'>-</Data>
        <Data Name='TargetOutboundDomainName'>-</Data>
        <Data Name='VirtualAccount'>%%1843</Data>
        <Data Name='TargetLinkedLogonId'>0x0</Data>
        <Data Name='ElevatedToken'>%%1842</Data>
    </EventData>
</Event>
        "#;

        let extractor = LogonExtractor::new();
        let result = extractor.parse_login_event(xml);

        assert!(result.is_ok(), "parse_login_event should succeed");

        let (timestamp, logon_event) = result.unwrap();

        let expected_timestamp = DateTime::parse_from_rfc3339("2025-07-22T16:25:08.8954670Z")
            .expect("Failed to parse expected timestamp")
            .with_timezone(&Utc);
        assert_eq!(timestamp, expected_timestamp);

        assert_eq!(logon_event.username, "SYSTEM@NT AUTHORITY");
        assert_eq!(logon_event.source_ip, "-");
        assert!(matches!(logon_event.variant, LogonVariant::Service));

        println!("Successfully tested parse_login_event:");
        println!("Timestamp: {}", timestamp);
        println!("Username: {}", logon_event.username);
        println!("Source IP: {}", logon_event.source_ip);
        println!("Logon Type: {}", logon_event.variant);
    }

    #[test]
    fn test_parse_login_event_with_missing_data() {
        let xml = r#"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <TimeCreated SystemTime='2025-07-22T16:25:08.8954670Z'/>
    </System>
    <EventData>
        <Data Name='TargetUserName'>TESTUSER</Data>
    </EventData>
</Event>
        "#;

        let extractor = LogonExtractor::new();
        let result = extractor.parse_login_event(xml);

        assert!(
            result.is_ok(),
            "parse_login_event should handle missing data gracefully"
        );

        let (timestamp, logon_event) = result.unwrap();

        let expected_timestamp = DateTime::parse_from_rfc3339("2025-07-22T16:25:08.8954670Z")
            .expect("Failed to parse expected timestamp")
            .with_timezone(&Utc);
        assert_eq!(timestamp, expected_timestamp);

        assert_eq!(logon_event.username, "TESTUSER");
        assert_eq!(logon_event.source_ip, "N/A");
        assert!(matches!(logon_event.variant, LogonVariant::Invalid(_)));

        println!("Successfully tested parse_login_event with missing data:");
        println!("Username: {}", logon_event.username);
        println!("Source IP: {}", logon_event.source_ip);
        println!("Logon Type: {}", logon_event.variant);
    }

    #[test]
    fn test_parse_login_event_invalid_xml() {
        let invalid_xml = r#"
<Invalid>
    XML
</Invalid>
        "#;

        let extractor = LogonExtractor::new();
        let result = extractor.parse_login_event(invalid_xml);

        assert!(
            result.is_err(),
            "parse_login_event should fail with invalid XML"
        );

        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("Failed to parse XML"),
            "Error should mention XML parsing failure"
        );
    }

    #[test]
    fn test_logon_variant_parsing() {
        let test_cases = vec![
            ("2", LogonVariant::Interactive),
            ("3", LogonVariant::Network),
            ("4", LogonVariant::Batch),
            ("5", LogonVariant::Service),
            ("7", LogonVariant::Unlock),
            ("8", LogonVariant::NetworkCleartext),
            ("9", LogonVariant::NewCredentials),
            ("10", LogonVariant::RemoteInteractive),
            ("11", LogonVariant::CachedInteractive),
            ("12", LogonVariant::CachedRemoteInteractive),
            ("13", LogonVariant::CachedUnlock),
            ("99", LogonVariant::Unknown(99)),
        ];

        for (input, expected) in test_cases {
            let result = LogonVariant::from_string(input);
            assert_eq!(result.as_number(), expected.as_number());
        }

        let invalid = LogonVariant::from_string("invalid");
        assert!(!invalid.is_valid());
        assert_eq!(invalid.as_number(), -1);
    }
}
