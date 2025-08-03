use anyhow::Result;

#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("Failed to parse XML: {0}")]
    XmlParseError(String),

    #[error("Failed to parse timestamp: {0}")]
    TimestampParseError(String),

    #[error("Failed to query events: {0}")]
    EventQueryError(String),

    #[error("Failed to send event to channel")]
    ChannelSendError,
}

pub type SentinelResult<T> = Result<T, SentinelError>;
