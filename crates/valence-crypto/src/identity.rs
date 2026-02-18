//! Node identity — Ed25519 keypair management per §1.

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};

/// A node's identity keypair.
#[derive(Clone)]
pub struct NodeIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl NodeIdentity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng {};
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    /// Create from a 32-byte seed (deterministic).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    /// Hex-encoded public key (the node ID).
    pub fn node_id(&self) -> String {
        hex::encode(self.verifying_key.as_bytes())
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Get the raw public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Get the signing key (for KEY_ROTATE dual-signing).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

/// Verify an Ed25519 signature.
pub fn verify_signature(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let Ok(pk_bytes) = hex::decode(public_key_hex) else { return false };
    let Ok(sig_bytes) = hex::decode(signature_hex) else { return false };

    if pk_bytes.len() != 32 || sig_bytes.len() != 64 {
        return false;
    }

    let Ok(pk_array): Result<[u8; 32], _> = pk_bytes.try_into() else { return false };
    let Ok(sig_array): Result<[u8; 64], _> = sig_bytes.try_into() else { return false };

    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_array) else { return false };
    let signature = Signature::from_bytes(&sig_array);

    verifying_key.verify(message, &signature).is_ok()
}

/// Compute the VDF input from a public key (just the raw bytes).
pub fn vdf_input(public_key_hex: &str) -> Option<Vec<u8>> {
    hex::decode(public_key_hex).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_from_seed() {
        // Conformance test keypair A
        let seed = [0u8; 32];
        let mut seed_a = seed;
        seed_a[31] = 1;
        let identity = NodeIdentity::from_seed(&seed_a);
        assert_eq!(
            identity.node_id(),
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"
        );
    }

    #[test]
    fn keypair_b_from_seed() {
        let mut seed = [0u8; 32];
        seed[31] = 2;
        let identity = NodeIdentity::from_seed(&seed);
        assert_eq!(
            identity.node_id(),
            "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674"
        );
    }

    #[test]
    fn sign_and_verify() {
        let identity = NodeIdentity::generate();
        let message = b"hello world";
        let sig = identity.sign(message);
        let sig_hex = hex::encode(&sig);
        assert!(verify_signature(&identity.node_id(), message, &sig_hex));
    }

    #[test]
    fn verify_wrong_message_fails() {
        let identity = NodeIdentity::generate();
        let sig = identity.sign(b"hello world");
        let sig_hex = hex::encode(&sig);
        assert!(!verify_signature(&identity.node_id(), b"wrong message", &sig_hex));
    }
}
