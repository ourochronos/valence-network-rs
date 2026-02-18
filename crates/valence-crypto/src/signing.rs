//! Message signing and verification per §2.

use serde_json::Value;
use valence_core::canonical::{content_address, signing_body_bytes};
use valence_core::message::Envelope;
use crate::identity::{NodeIdentity, verify_signature};

/// Sign a message, producing a complete Envelope.
pub fn sign_message(
    identity: &NodeIdentity,
    msg_type: valence_core::message::MessageType,
    payload: Value,
    timestamp: i64,
) -> Envelope {
    let from = identity.node_id();
    let type_str = serde_json::to_value(&msg_type)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    let body_bytes = signing_body_bytes(&from, &type_str, timestamp, &payload);
    let id = content_address(&from, &type_str, timestamp, &payload);
    let signature = hex::encode(identity.sign(&body_bytes));

    Envelope {
        version: 0,
        msg_type,
        id,
        from,
        timestamp,
        payload,
        signature,
    }
}

/// Verify an envelope's signature.
pub fn verify_envelope(envelope: &Envelope) -> bool {
    let type_str = serde_json::to_value(&envelope.msg_type)
        .map(|v| v.as_str().unwrap_or("").to_string())
        .unwrap_or_default();

    let body_bytes = signing_body_bytes(
        &envelope.from,
        &type_str,
        envelope.timestamp,
        &envelope.payload,
    );

    // Verify signature
    if !verify_signature(&envelope.from, &body_bytes, &envelope.signature) {
        return false;
    }

    // Verify content address
    let expected_id = content_address(&envelope.from, &type_str, envelope.timestamp, &envelope.payload);
    envelope.id == expected_id
}

/// Validate an envelope per §2 rules (timestamp, size, etc.).
pub fn validate_envelope(envelope: &Envelope, current_time_ms: i64) -> Result<(), ValidationError> {
    use valence_core::constants::*;

    // Version check
    if envelope.version != 0 {
        return Err(ValidationError::UnsupportedVersion(envelope.version));
    }

    // Timestamp tolerance (±5 minutes)
    let diff = (envelope.timestamp - current_time_ms).abs();
    if diff > TIMESTAMP_TOLERANCE_MS {
        return Err(ValidationError::TimestampOutOfRange {
            message_ts: envelope.timestamp,
            local_ts: current_time_ms,
            diff_ms: diff,
        });
    }

    // Payload size
    let payload_str = serde_json::to_string(&envelope.payload).unwrap_or_default();
    if payload_str.len() > MAX_PAYLOAD_SIZE {
        return Err(ValidationError::PayloadTooLarge {
            size: payload_str.len(),
            max: MAX_PAYLOAD_SIZE,
        });
    }

    // Signature verification
    if !verify_envelope(envelope) {
        return Err(ValidationError::InvalidSignature);
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u32),

    #[error("Timestamp out of range: message={message_ts}, local={local_ts}, diff={diff_ms}ms")]
    TimestampOutOfRange {
        message_ts: i64,
        local_ts: i64,
        diff_ms: i64,
    },

    #[error("Payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("Invalid signature or content address")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use valence_core::message::MessageType;

    #[test]
    fn sign_and_verify_roundtrip() {
        let identity = NodeIdentity::generate();
        let payload = serde_json::json!({"title": "test"});
        let envelope = sign_message(
            &identity,
            MessageType::Propose,
            payload,
            1700000000000,
        );
        assert!(verify_envelope(&envelope));
    }

    #[test]
    fn tampered_payload_fails() {
        let identity = NodeIdentity::generate();
        let payload = serde_json::json!({"title": "test"});
        let mut envelope = sign_message(
            &identity,
            MessageType::Propose,
            payload,
            1700000000000,
        );
        envelope.payload = serde_json::json!({"title": "tampered"});
        assert!(!verify_envelope(&envelope));
    }

    #[test]
    fn validate_timestamp_rejection() {
        let identity = NodeIdentity::generate();
        let payload = serde_json::json!({"title": "test"});
        let envelope = sign_message(
            &identity,
            MessageType::Propose,
            payload,
            1700000000000,
        );
        // Current time far from message time
        let result = validate_envelope(&envelope, 1700001000000);
        assert!(matches!(result, Err(ValidationError::TimestampOutOfRange { .. })));
    }
}
