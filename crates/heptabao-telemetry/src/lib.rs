#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Bounded telemetry events with an allowlist for low-cardinality labels.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use heptabao_domain::Id;

const ALLOWED_LABELS: &[&str] = &[
    "backend",
    "kind",
    "operation",
    "outcome",
    "state",
    "generation_bucket",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryEvent {
    name: Id,
    labels: BTreeMap<Id, Id>,
}

impl TelemetryEvent {
    pub fn new(name: Id, labels: BTreeMap<Id, Id>) -> Result<Self, TelemetryError> {
        for key in labels.keys() {
            if !ALLOWED_LABELS.contains(&key.as_str()) {
                return Err(TelemetryError::ForbiddenLabel);
            }
        }
        Ok(Self { name, labels })
    }

    pub fn name(&self) -> &Id {
        &self.name
    }

    pub fn labels(&self) -> &BTreeMap<Id, Id> {
        &self.labels
    }
}

#[derive(Debug, Default)]
pub struct MemoryTelemetry {
    events: Vec<TelemetryEvent>,
}

impl MemoryTelemetry {
    pub fn record(&mut self, event: TelemetryEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[TelemetryEvent] {
        &self.events
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryError {
    ForbiddenLabel,
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("telemetry label is not in the bounded allowlist")
    }
}

impl Error for TelemetryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_or_high_cardinality_labels_are_rejected() -> Result<(), Box<dyn Error>> {
        let mut labels = BTreeMap::new();
        labels.insert(Id::parse("token")?, Id::parse("value")?);
        assert_eq!(
            Err(TelemetryError::ForbiddenLabel),
            TelemetryEvent::new(Id::parse("request_rejected")?, labels)
        );
        Ok(())
    }

    #[test]
    fn approved_labels_are_recorded_without_payloads() -> Result<(), Box<dyn Error>> {
        let mut labels = BTreeMap::new();
        labels.insert(Id::parse("operation")?, Id::parse("kv_read")?);
        labels.insert(Id::parse("outcome")?, Id::parse("completed")?);
        let event = TelemetryEvent::new(Id::parse("request_completed")?, labels)?;
        let mut sink = MemoryTelemetry::default();
        sink.record(event);
        assert_eq!(1, sink.events().len());
        Ok(())
    }
}
