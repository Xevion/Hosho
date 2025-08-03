use chrono::{DateTime, Utc};
use sentinel::listener::logon::{LogonVariant, parse_login_event};

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

    let result = parse_login_event(xml);

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
        <EventRecordID>0</EventRecordID>
    </System>
    <EventData>
        <Data Name='TargetUserName'>TESTUSER</Data>
    </EventData>
</Event>
        "#;

    let result = parse_login_event(xml);

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

    let result = parse_login_event(invalid_xml);

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
