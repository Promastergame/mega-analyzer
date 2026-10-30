#![allow(missing_docs)]

use omnisec_crypto::chacha20poly1305::{self, Key, Nonce};
use omnisec_crypto::fill_os_random;

const MAX_PACKET_LEN: usize = 1024 * 1024;

#[derive(Debug)]
pub enum ObfsError {
    EncryptionFailed(String),
    DecryptionFailed(String),
    InvalidPadding,
    PacketTooShort,
    PacketTooLarge,
}

impl std::fmt::Display for ObfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncryptionFailed(msg) => write!(f, "Encryption failed: {msg}"),
            Self::DecryptionFailed(msg) => write!(f, "Decryption failed: {msg}"),
            Self::InvalidPadding => write!(f, "Invalid padding length"),
            Self::PacketTooShort => write!(f, "Packet too short"),
            Self::PacketTooLarge => write!(f, "Packet too large"),
        }
    }
}

impl std::error::Error for ObfsError {}

pub struct Obfuscator {
    key: Key,
}

impl Obfuscator {
    /// Initialize with a 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: Key(*key) }
    }

    /// Obfuscates (encrypts + shapes) a network packet.
    /// Format:
    /// [Nonce (12 bytes)] | [Encrypted Data] | [MAC (16 bytes)]
    /// Inside Encrypted Data: [Original Data Length (2 bytes)] | [Original Data] | [Random Padding]
    /// Nonces come from the OS CSPRNG, including across threads and processes.
    /// Rotate a shared key before sending 2^32 packets under it.
    pub fn obfuscate(
        &self,
        data: &[u8],
        min_padding: usize,
        max_padding: usize,
    ) -> Result<Vec<u8>, ObfsError> {
        if data.len() > u16::MAX as usize {
            return Err(ObfsError::PacketTooLarge);
        }

        if min_padding > max_padding {
            return Err(ObfsError::InvalidPadding);
        }
        if max_padding > MAX_PACKET_LEN - 30 - data.len() {
            return Err(ObfsError::PacketTooLarge);
        }
        let random_error = |error: std::io::Error| ObfsError::EncryptionFailed(error.to_string());
        let mut random = [0u8; 20];
        fill_os_random(&mut random).map_err(random_error)?;
        let choice = u64::from_le_bytes(random[..8].try_into().expect("eight bytes"));
        let padding_len = min_padding + (choice % (max_padding - min_padding + 1) as u64) as usize;

        // Construct inner payload: [Length(2)] + [Data] + [Padding]
        let mut inner_payload = Vec::with_capacity(2 + data.len() + padding_len);
        inner_payload.extend_from_slice(&(data.len() as u16).to_le_bytes());
        inner_payload.extend_from_slice(data);

        let padding_start = inner_payload.len();
        inner_payload.resize(padding_start + padding_len, 0);
        fill_os_random(&mut inner_payload[padding_start..]).map_err(random_error)?;

        // Generate Nonce
        let nonce_bytes: [u8; 12] = random[8..].try_into().expect("twelve-byte nonce");
        let nonce = Nonce(nonce_bytes);

        // Encrypt (output = ciphertext ++ 16-byte MAC)
        let ciphertext = chacha20poly1305::seal(&self.key, &nonce, b"", &inner_payload);

        // Construct final packet
        let mut final_packet = Vec::with_capacity(12 + ciphertext.len());
        final_packet.extend_from_slice(&nonce_bytes);
        final_packet.extend_from_slice(&ciphertext);

        Ok(final_packet)
    }

    /// Deobfuscates (decrypts + removes shaping) a network packet.
    pub fn deobfuscate(&self, data: &[u8]) -> Result<Vec<u8>, ObfsError> {
        if data.len() < 12 + 16 + 2 {
            // Nonce + MAC + Length
            return Err(ObfsError::PacketTooShort);
        }

        let nonce = Nonce(data[0..12].try_into().expect("12-byte nonce"));
        let ciphertext = &data[12..];

        let plaintext = chacha20poly1305::open(&self.key, &nonce, b"", ciphertext).ok_or(
            ObfsError::DecryptionFailed("authentication failed".to_string()),
        )?;

        if plaintext.len() < 2 {
            return Err(ObfsError::PacketTooShort);
        }

        let orig_len = u16::from_le_bytes([plaintext[0], plaintext[1]]) as usize;

        if plaintext.len() < 2 + orig_len {
            return Err(ObfsError::InvalidPadding);
        }

        Ok(plaintext[2..2 + orig_len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscation_roundtrip() {
        let key = [42u8; 32];
        let obfs = Obfuscator::new(&key);
        let data = b"Hello, MegaAnalyzer!";

        let obfuscated = obfs.obfuscate(data, 10, 50).unwrap();
        assert!(obfuscated.len() >= 12 + 16 + 2 + data.len() + 10);

        let deobfuscated = obfs.deobfuscate(&obfuscated).unwrap();
        assert_eq!(data, deobfuscated.as_slice());
    }

    #[test]
    fn rejects_ciphertext_changes_without_a_new_tag() {
        let obfs = Obfuscator::new(&[42; 32]);
        let packet = obfs.obfuscate(b"Authenticated message", 0, 0).unwrap();
        for byte in 0..packet.len() {
            for bit in 0..8 {
                let mut changed = packet.clone();
                changed[byte] ^= 1 << bit;
                assert!(
                    obfs.deobfuscate(&changed).is_err(),
                    "accepted byte {byte}, bit {bit}"
                );
            }
        }
    }

    #[test]
    fn concurrent_instances_do_not_repeat_nonces() {
        use std::collections::HashSet;
        use std::sync::{Arc, Barrier};
        let start = Arc::new(Barrier::new(16));
        let workers: Vec<_> = (0..16)
            .map(|_| {
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    let obfs = Obfuscator::new(&[42; 32]);
                    start.wait();
                    (0..4096)
                        .map(|_| {
                            let packet = obfs.obfuscate(b"message", 0, 0).unwrap();
                            <[u8; 12]>::try_from(&packet[..12]).unwrap()
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut nonces = HashSet::new();
        for worker in workers {
            for nonce in worker.join().unwrap() {
                assert!(nonces.insert(nonce), "nonce reused under the same key");
            }
        }
    }

    #[test]
    fn rejects_invalid_padding_before_allocation() {
        let obfs = Obfuscator::new(&[42; 32]);
        assert!(matches!(
            obfs.obfuscate(b"x", 2, 1),
            Err(ObfsError::InvalidPadding)
        ));
        assert!(matches!(
            obfs.obfuscate(b"x", 0, usize::MAX),
            Err(ObfsError::PacketTooLarge)
        ));
    }
}
