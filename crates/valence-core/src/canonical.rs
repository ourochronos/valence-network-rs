//! JCS (RFC 8785) canonicalization and content addressing.
//!
//! All JSON serialization for signing and hashing MUST follow RFC 8785.
//! See §2 of the v0 spec.

use sha2::{Digest, Sha256};
use serde_json::Value;

/// Canonicalize a JSON value per RFC 8785 (JCS).
///
/// - Object keys sorted lexicographically by Unicode code point
/// - No whitespace between tokens
/// - Null values included (not omitted)
/// - Recursively applied to nested objects
pub fn canonicalize(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        Value::Number(n) => {
            // RFC 8785: numbers serialized per ECMAScript rules
            // For integers (which is all we use per §2), this is straightforward
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                // Float — shouldn't appear in protocol messages, but handle gracefully
                n.to_string()
            }
        }
        Value::String(s) => {
            // JSON string escaping
            serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s))
        }
        Value::Array(arr) => {
            let elements: Vec<String> = arr.iter().map(canonicalize).collect();
            format!("[{}]", elements.join(","))
        }
        Value::Object(obj) => {
            // Keys sorted lexicographically by Unicode code point
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let pairs: Vec<String> = keys
                .iter()
                .map(|k| {
                    let key_str = serde_json::to_string(*k).unwrap_or_else(|_| format!("\"{}\"", k));
                    let val_str = canonicalize(obj.get(*k).unwrap());
                    format!("{}:{}", key_str, val_str)
                })
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

/// Compute the SHA-256 hash of canonical JSON bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute the content address (message ID) from a signing body.
/// The signing body is the JCS-canonicalized form of {from, payload, timestamp, type}.
pub fn content_address(from: &str, msg_type: &str, timestamp: i64, payload: &Value) -> String {
    let signing_body = signing_body_json(from, msg_type, timestamp, payload);
    let canonical = canonicalize(&signing_body);
    sha256_hex(canonical.as_bytes())
}

/// Construct the signing body JSON value.
/// Per §2: keys in lexicographic order: from, payload, timestamp, type.
/// Version is deliberately excluded.
pub fn signing_body_json(from: &str, msg_type: &str, timestamp: i64, payload: &Value) -> Value {
    serde_json::json!({
        "from": from,
        "payload": payload,
        "timestamp": timestamp,
        "type": msg_type,
    })
}

/// Compute the signing body bytes (JCS-canonicalized).
pub fn signing_body_bytes(from: &str, msg_type: &str, timestamp: i64, payload: &Value) -> Vec<u8> {
    let body = signing_body_json(from, msg_type, timestamp, payload);
    canonicalize(&body).into_bytes()
}

/// Compute a Merkle root over a set of proposal IDs.
/// Per §11: leaves = SHA-256(id), sorted lexicographically, binary tree, left-biased for odd counts.
/// Empty set → SHA-256 of empty byte string.
pub fn merkle_root(proposal_ids: &[String]) -> String {
    if proposal_ids.is_empty() {
        return sha256_hex(b"");
    }

    // Sort IDs lexicographically
    let mut sorted_ids = proposal_ids.to_vec();
    sorted_ids.sort();

    // Compute leaf hashes
    let mut hashes: Vec<Vec<u8>> = sorted_ids
        .iter()
        .map(|id| {
            let mut hasher = Sha256::new();
            hasher.update(id.as_bytes());
            hasher.finalize().to_vec()
        })
        .collect();

    // Build tree bottom-up, left-biased for odd counts
    while hashes.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i + 1 < hashes.len() {
            let mut hasher = Sha256::new();
            hasher.update(&hashes[i]);
            hasher.update(&hashes[i + 1]);
            next_level.push(hasher.finalize().to_vec());
            i += 2;
        }
        // Odd element promoted
        if i < hashes.len() {
            next_level.push(hashes[i].clone());
        }
        hashes = next_level;
    }

    hex::encode(&hashes[0])
}

/// Compute manifest hash for erasure-coded shards.
/// Per §6: SHA-256 of shard_hashes sorted lexicographically as hex strings,
/// concatenated without delimiters, then appended with content_hash hex string,
/// all as UTF-8 bytes.
pub fn manifest_hash(shard_hashes: &[String], content_hash: &str) -> String {
    let mut sorted = shard_hashes.to_vec();
    sorted.sort();
    let mut input = String::new();
    for hash in &sorted {
        input.push_str(hash);
    }
    input.push_str(content_hash);
    sha256_hex(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // === Conformance tests from conformance-tests.md ===

    #[test]
    fn canon_01_nested_object_sorting() {
        let input = json!({"z": 1, "a": {"c": 3, "b": 2}});
        assert_eq!(canonicalize(&input), r#"{"a":{"b":2,"c":3},"z":1}"#);
    }

    #[test]
    fn canon_02_unicode_key_ordering() {
        let input = json!({"ä": "ö", "a": "b"});
        assert_eq!(canonicalize(&input), r#"{"a":"b","ä":"ö"}"#);
    }

    #[test]
    fn canon_03_null_values_included() {
        let input = json!({"b": null, "a": 1});
        assert_eq!(canonicalize(&input), r#"{"a":1,"b":null}"#);
    }

    #[test]
    fn canon_04_integers_only() {
        let input = json!({"float_as_int": 10000, "int": 1, "neg": -1, "zero": 0});
        assert_eq!(
            canonicalize(&input),
            r#"{"float_as_int":10000,"int":1,"neg":-1,"zero":0}"#
        );
    }

    #[test]
    fn addr_01_content_address() {
        // From conformance-tests.md ADDR-01
        let from = "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29";
        let timestamp = 1700000000000i64;
        let payload = json!({"title": "Test Proposal", "body": "Hello world"});

        let id = content_address(from, "PROPOSE", timestamp, &payload);
        assert_eq!(id, "9f827d6492e180166a78958594a000b88063ba7a4ab3474749732cca5d60fdb3");
    }

    #[test]
    fn addr_02_version_excluded() {
        // Changing version doesn't change the signing body or ID
        let from = "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29";
        let timestamp = 1700000000000i64;
        let payload = json!({"title": "Test Proposal", "body": "Hello world"});

        let id = content_address(from, "PROPOSE", timestamp, &payload);
        // Same ID regardless of version field (version not in signing body)
        assert_eq!(id, "9f827d6492e180166a78958594a000b88063ba7a4ab3474749732cca5d60fdb3");
    }

    #[test]
    fn merkle_01_empty() {
        assert_eq!(
            merkle_root(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn merkle_02_single() {
        let ids = vec!["a1b2c3d4e5f6".to_string()];
        assert_eq!(
            merkle_root(&ids),
            "bde81e9384b7848e57951ec32c7344459233235bfa519d7396ae3406014a06f4"
        );
    }

    #[test]
    fn merkle_03_two() {
        let ids = vec!["a1b2c3d4e5f6".to_string(), "b2c3d4e5f6a1".to_string()];
        assert_eq!(
            merkle_root(&ids),
            "cd4eacb7493443618c0a6325db660723d010873c4e188e62eda660021b0de9a0"
        );
    }

    #[test]
    fn merkle_04_three() {
        let ids = vec![
            "a1b2c3d4e5f6".to_string(),
            "b2c3d4e5f6a1".to_string(),
            "c3d4e5f6a1b2".to_string(),
        ];
        assert_eq!(
            merkle_root(&ids),
            "e0b65593156cd8bd67f8c000a8bbd71fe708ec30b05a903adc64273c2c81a70e"
        );
    }

    #[test]
    fn merkle_05_five() {
        let ids = vec![
            "a1b2c3d4e5f6".to_string(),
            "b2c3d4e5f6a1".to_string(),
            "c3d4e5f6a1b2".to_string(),
            "d4e5f6a1b2c3".to_string(),
            "e5f6a1b2c3d4".to_string(),
        ];
        assert_eq!(
            merkle_root(&ids),
            "d15072ca65d39c1f12e1f402c49eb9d2760d7838aad99f52801d58ac3bb8398d"
        );
    }
}
