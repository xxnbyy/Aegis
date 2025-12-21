use common::crypto;
use common::protocol::{PayloadEnvelope, ProcessInfo, SystemInfo};
use prost::Message;
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::pkcs8::EncodePublicKey;

use crate::model::{
    Decryption, GetGraphViewportInput, OpenArtifactInput, OpenArtifactOptions, Page, Source,
    ViewportLevel,
};
use crate::{Console, ConsoleConfig};

fn build_test_artifact_bytes(
    passphrase: &str,
) -> Result<(Vec<u8>, String, String), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let public_key = RsaPublicKey::from(&private_key);
    let public_der = public_key.to_public_key_der()?.as_bytes().to_vec();
    let org_key_fp = crypto::org_pubkey_fingerprint_xxh64(public_der.as_slice());

    let mut kdf_salt = [0u8; crypto::AES_KDF_SALT_LEN];
    rand::RngCore::fill_bytes(&mut rng, &mut kdf_salt);
    let host_uuid = crypto::get_or_create_host_uuid("dev")?;
    let header = crypto::build_aes_header_v1(&kdf_salt, &host_uuid, org_key_fp);

    let mut session_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut session_key);

    let kek_bytes = crypto::derive_kek_argon2id(passphrase.as_bytes(), kdf_salt.as_slice())?;
    let kek = aes_kw::Kek::from(kek_bytes);
    let user_slot = kek.wrap_vec(session_key.as_slice())?;
    assert_eq!(user_slot.len(), 40);

    let rsa_ct = public_key.encrypt(
        &mut rng,
        rsa::Oaep::new::<sha2::Sha256>(),
        session_key.as_slice(),
    )?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(header.as_slice());
    bytes.extend_from_slice(user_slot.as_slice());
    bytes.extend_from_slice(rsa_ct.as_slice());

    let sys = PayloadEnvelope::system_info(SystemInfo {
        hostname: "h".to_string(),
        os_version: "o".to_string(),
        kernel_version: "k".to_string(),
        ip_addresses: vec!["10.0.0.1".to_string()],
        boot_time: 1,
    })
    .encode_to_vec();
    bytes.extend_from_slice(crypto::encrypt(sys.as_slice(), session_key.as_slice())?.as_slice());

    let parent = PayloadEnvelope::process_info(ProcessInfo {
        pid: 100,
        ppid: 0,
        name: "p100".to_string(),
        cmdline: "p100".to_string(),
        exe_path: "C:\\p100.exe".to_string(),
        uid: 0,
        start_time: 2_000,
        is_ghost: false,
        is_mismatched: false,
        has_floating_code: false,
        exec_id: 1,
        exec_id_quality: "windows:psn".to_string(),
    })
    .encode_to_vec();
    bytes.extend_from_slice(crypto::encrypt(parent.as_slice(), session_key.as_slice())?.as_slice());

    let child = PayloadEnvelope::process_info(ProcessInfo {
        pid: 200,
        ppid: 100,
        name: "p200".to_string(),
        cmdline: "p200".to_string(),
        exe_path: "C:\\p200.exe".to_string(),
        uid: 0,
        start_time: 3_000,
        is_ghost: true,
        is_mismatched: false,
        has_floating_code: false,
        exec_id: 2,
        exec_id_quality: "windows:psn".to_string(),
    })
    .encode_to_vec();
    bytes.extend_from_slice(crypto::encrypt(child.as_slice(), session_key.as_slice())?.as_slice());

    crypto::append_hmac_sig_trailer_v1(&mut bytes, &session_key)?;

    let priv_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?
        .to_string();
    let host_uuid_str = uuid::Uuid::from_bytes(host_uuid).to_string();
    Ok((bytes, priv_pem, host_uuid_str))
}

#[test]
fn open_artifact_with_passphrase_and_viewport_level0_connectivity()
-> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw")?;
    let dir = tempfile::tempdir()?;
    let p = dir.path().join("t.aes");
    std::fs::write(p.as_path(), artifact_bytes.as_slice())?;

    let mut c = Console::new(ConsoleConfig::default());
    let out = c.open_artifact(OpenArtifactInput {
        source: Source::LocalPath {
            path: p.display().to_string(),
        },
        decryption: Decryption::UserPassphrase {
            passphrase: "pw".to_string(),
        },
        options: OpenArtifactOptions {
            verify_hmac_if_present: true,
        },
    })?;
    assert!(out.sealed);

    let v = c.get_graph_viewport(GetGraphViewportInput {
        case_id: out.case_id,
        level: ViewportLevel::L0,
        viewport_bbox: None,
        risk_score_threshold: Some(80),
        center_node_id: None,
        page: None,
    })?;
    assert!(v.nodes.len() >= 2);
    assert!(
        v.edges
            .iter()
            .any(|e| matches!(e.r#type, crate::EdgeType::ParentOf))
    );
    Ok(())
}

#[test]
fn close_case_makes_case_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw2")?;
    let dir = tempfile::tempdir()?;
    let p = dir.path().join("t2.aes");
    std::fs::write(p.as_path(), artifact_bytes.as_slice())?;

    let mut c = Console::new(ConsoleConfig::default());
    let out = c.open_artifact(OpenArtifactInput {
        source: Source::LocalPath {
            path: p.display().to_string(),
        },
        decryption: Decryption::UserPassphrase {
            passphrase: "pw2".to_string(),
        },
        options: OpenArtifactOptions::default(),
    })?;
    c.close_case(out.case_id.as_str())?;

    let err = c
        .get_graph_viewport(GetGraphViewportInput {
            case_id: out.case_id,
            level: ViewportLevel::L2,
            viewport_bbox: None,
            risk_score_threshold: None,
            center_node_id: None,
            page: Some(Page {
                cursor: None,
                limit: Some(10),
            }),
        })
        .err()
        .ok_or("expected error")?;
    assert!(matches!(
        err,
        common::error::AegisError::ProtocolError {
            code: Some(common::error::ErrorCode::Console721),
            ..
        }
    ));
    Ok(())
}

#[test]
fn open_artifact_rejects_invalid_hmac_when_required() -> Result<(), Box<dyn std::error::Error>> {
    let (mut artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw3")?;
    if artifact_bytes.len() > crypto::HMAC_SIG_TRAILER_LEN + 1 {
        let i = artifact_bytes.len() - crypto::HMAC_SIG_TRAILER_LEN - 1;
        artifact_bytes[i] ^= 0x01;
    }

    let dir = tempfile::tempdir()?;
    let p = dir.path().join("t3.aes");
    std::fs::write(p.as_path(), artifact_bytes.as_slice())?;

    let mut c = Console::new(ConsoleConfig::default());
    let err = c
        .open_artifact(OpenArtifactInput {
            source: Source::LocalPath {
                path: p.display().to_string(),
            },
            decryption: Decryption::UserPassphrase {
                passphrase: "pw3".to_string(),
            },
            options: OpenArtifactOptions {
                verify_hmac_if_present: true,
            },
        })
        .err()
        .ok_or("expected error")?;

    assert!(matches!(
        err,
        common::error::AegisError::CryptoError {
            code: Some(common::error::ErrorCode::Crypto003),
            ..
        }
    ));
    Ok(())
}
