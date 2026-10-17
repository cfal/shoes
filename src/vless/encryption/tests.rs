use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use super::{
    crypto::{Aead, Cipher, Ctr, MAX_NONCE},
    keys::ServerKey,
    mask::HeaderMask,
};

mod lifecycle;
mod transports;

pub(super) fn fixtures() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/vless_encryption/vectors.json"
    ))
    .unwrap()
}

pub(super) fn bytes(value: &Value, field: &str) -> Vec<u8> {
    let hex = value[field].as_str().unwrap();
    assert!(hex.len().is_multiple_of(2));
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn binary_context_kdfs_match_go() {
    for vector in fixtures()["kdf"].as_array().unwrap() {
        assert_eq!(
            blake3::derive_key_bytes(&bytes(vector, "context"), &bytes(vector, "material"))
                .as_slice(),
            bytes(vector, "key")
        );
    }
}

#[test]
fn go_encapsulation_decapsulates_with_imported_seed() {
    for vector in fixtures()["seeds"].as_array().unwrap() {
        let server = ServerKey::new(&bytes(vector, "seed")).unwrap();
        assert_eq!(server.public, bytes(vector, "public"));
        assert_eq!(
            server
                .exchange(&bytes(vector, "ciphertext"))
                .unwrap()
                .as_ref(),
            bytes(vector, "secret")
        );
    }
}

#[test]
#[ignore = "exports randomized test-only ciphertexts for independent Go verification"]
fn export_rust_encapsulations() {
    let output =
        std::env::var_os("VLESS_RUST_VECTORS").expect("set VLESS_RUST_VECTORS to the output path");
    let hex = |data: &[u8]| data.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let vectors: Vec<_> = fixtures()["seeds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vector| {
            let seed = bytes(vector, "seed");
            let key = ServerKey::new(&seed).unwrap();
            let client = super::keys::ClientKey::new(&key.public).unwrap();
            let (ciphertext, secret) = client.exchange().unwrap();
            serde_json::json!({
                "seed": hex(&seed),
                "public": hex(&key.public),
                "ciphertext": hex(&ciphertext),
                "secret": hex(secret.as_ref()),
            })
        })
        .collect();
    std::fs::write(output, serde_json::to_vec_pretty(&vectors).unwrap()).unwrap();
}

#[test]
fn aead_contexts_and_nonce_sequence_match_go() {
    for vector in fixtures()["aead"].as_array().unwrap() {
        let cipher = if vector["aes"].as_bool().unwrap() {
            Cipher::Aes256Gcm
        } else {
            Cipher::ChaCha20Poly1305
        };
        let mut aead = Aead::new(
            &bytes(vector, "context"),
            &bytes(vector, "material"),
            cipher,
        )
        .unwrap();
        let plain = bytes(vector, "plaintext");
        let header = bytes(vector, "header");
        assert_eq!(aead.seal(&plain, &header).unwrap(), bytes(vector, "one"));
        assert_eq!(
            aead.seal_at(MAX_NONCE, &plain, &[]).unwrap(),
            bytes(vector, "max")
        );
        assert_eq!(aead.seal(&plain, &header).unwrap(), bytes(vector, "two"));
    }
}

#[test]
fn ctr_vectors_match_go_across_counter_carries() {
    for vector in fixtures()["ctr"].as_array().unwrap() {
        let iv = bytes(vector, "iv").try_into().unwrap();
        for split in 0..=32 {
            let mut ctr = Ctr::new(&bytes(vector, "material"), &iv).unwrap();
            let mut actual = bytes(vector, "plaintext");
            ctr.apply(&mut actual[..split]).unwrap();
            for chunk in actual[split..].chunks_mut(5) {
                ctr.apply(chunk).unwrap();
            }
            assert_eq!(actual, bytes(vector, "ciphertext"));
        }
    }
}

#[test]
fn permissive_header_masks_match_go_at_every_split() {
    for vector in fixtures()["mask"].as_array().unwrap() {
        let iv = bytes(vector, "iv").try_into().unwrap();
        let expected = bytes(vector, "ciphertext");
        for split in 0..expected.len() {
            let mut mask = HeaderMask::new(&bytes(vector, "material"), &iv, 0).unwrap();
            let mut actual = bytes(vector, "plaintext");
            mask.apply_write(&mut actual[..split]).unwrap();
            mask.apply_write(&mut actual[split..]).unwrap();
            assert_eq!(actual, expected);
        }
    }
}

pub(super) fn fixture_settings(mode: &str, resume: bool, keys: &[usize]) -> (String, String) {
    let private: Vec<Vec<u8>> = keys
        .iter()
        .enumerate()
        .map(|(i, size)| vec![i as u8 + 1; *size])
        .collect();
    let public: Vec<Vec<u8>> = private
        .iter()
        .map(|k| ServerKey::new(k).unwrap().public)
        .collect();
    let encode = |keys: &[Vec<u8>]| {
        keys.iter()
            .map(|k| URL_SAFE_NO_PAD.encode(k))
            .collect::<Vec<_>>()
            .join(".")
    };
    let rtt = if resume { "0rtt" } else { "1rtt" };
    let lifetime = if resume { "600s" } else { "0s" };
    (
        format!(
            "mlkem768x25519plus.{mode}.{rtt}.100-35-35.100-0-0.100-35-35.{}",
            encode(&public)
        ),
        format!(
            "mlkem768x25519plus.{mode}.{lifetime}.100-35-35.100-0-0.100-35-35.{}",
            encode(&private)
        ),
    )
}

pub(super) fn fixture_pair(
    mode: &str,
    resume: bool,
    keys: &[usize],
) -> (super::ClientEncryption, super::ServerEncryption) {
    let (encryption, decryption) = fixture_settings(mode, resume, keys);
    (
        super::ClientEncryption::new(&encryption).unwrap(),
        super::ServerEncryption::new(&decryption, Default::default()).unwrap(),
    )
}

#[tokio::test]
async fn fresh_and_resumed_handshakes_over_tiny_streams() {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for mode in ["native", "xorpub", "random"] {
        for keys in [&[32][..], &[64], &[32, 64], &[64, 32, 32], &[64, 64]] {
            for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
                for capacity in [1, 5, 32] {
                    let (client, server) = fixture_pair(mode, true, keys);
                    for resumed in [false, true] {
                        let (left, right) = tokio::io::duplex(capacity);
                        let request = vec![0x5a; 100];
                        let client_run = async {
                            let mut stream = client.handshake_cipher(left, cipher).await.unwrap();
                            assert_eq!(
                                stream.is_resumed(),
                                resumed,
                                "{mode} {keys:?} {cipher:?} {capacity}"
                            );
                            stream.write_all(&request).await.unwrap();
                            stream.flush().await.unwrap();
                            let mut reply = vec![0; request.len()];
                            stream.read_exact(&mut reply).await.unwrap();
                            assert_eq!(reply, request);
                        };
                        let server_run = async {
                            let mut stream = server.handshake(right).await.unwrap();
                            let mut received = vec![0; request.len()];
                            stream.read_exact(&mut received).await.unwrap();
                            assert_eq!(received, request);
                            stream.write_all(&received).await.unwrap();
                            stream.flush().await.unwrap();
                        };
                        tokio::time::timeout(Duration::from_secs(5), async {
                            tokio::join!(client_run, server_run);
                        })
                        .await
                        .unwrap_or_else(|_| {
                            panic!(
                                "handshake stalled: {mode} {keys:?} {cipher:?} {capacity} {resumed}"
                            )
                        });
                    }
                }
            }
        }
    }
}
