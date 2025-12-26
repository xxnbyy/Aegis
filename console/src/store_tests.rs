use common::crypto;
use common::error::{AegisError, ErrorCode};
use common::protocol::MAX_ARTIFACT_CHUNK_SIZE;
use common::protocol::{PayloadEnvelope, ProcessInfo, SystemInfo};
use prost::Message;
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::pkcs8::EncodePublicKey;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

use crate::model::{
    AnalyzeEvidenceChunkInput, AnalyzeEvidenceMeta, BBox, Decryption, GetAiInsightInput,
    GetGraphViewportInput, GetTaskInput, ListTasksInput, OpenArtifactInput, OpenArtifactOptions,
    Page, Source, TaskStatus, ViewportLevel,
};
use crate::store::PersistenceConfig;
use crate::{Console, ConsoleConfig};

fn new_console_with_temp_persistence(dir: &tempfile::TempDir) -> Console {
    let data_dir = dir.path().join("data");
    let db_path = data_dir.join("console.db");
    Console::new(ConsoleConfig {
        max_level01_nodes: 20_000,
        persistence: Some(PersistenceConfig { data_dir, db_path }),
    })
}

fn temp_console() -> Result<(tempfile::TempDir, Console), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let c = new_console_with_temp_persistence(&dir);
    Ok((dir, c))
}

fn upload_bytes_as_evidence(
    c: &mut Console,
    request_id: u64,
    bytes: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let chunk_size = 64usize;
    let mut task_id: Option<String> = None;
    let mut sequence_id: u64 = 0;

    let mut offset = 0usize;
    while offset < bytes.len() {
        let end = std::cmp::min(offset.saturating_add(chunk_size), bytes.len());
        let is_last = end == bytes.len();
        let out = c.analyze_evidence(AnalyzeEvidenceChunkInput {
            request_id,
            sequence_id,
            is_last,
            bytes: bytes[offset..end].to_vec(),
            meta: if sequence_id == 0 {
                Some(AnalyzeEvidenceMeta {
                    filename: Some("t.aes".to_string()),
                    content_type: Some("application/octet-stream".to_string()),
                })
            } else {
                None
            },
        })?;
        match task_id.as_ref() {
            None => task_id = Some(out.task_id),
            Some(prev) => assert_eq!(prev, &out.task_id),
        }
        assert_eq!(out.next_sequence_id, Some(sequence_id.saturating_add(1)));
        if is_last {
            assert_eq!(out.status, TaskStatus::Pending);
        } else {
            assert_eq!(out.status, TaskStatus::Uploading);
        }
        offset = end;
        sequence_id = sequence_id.saturating_add(1);
    }

    Ok(task_id.ok_or("missing task_id")?)
}

fn assert_err_code(err: AegisError, expected: ErrorCode) -> Result<(), Box<dyn std::error::Error>> {
    match err {
        AegisError::ProtocolError {
            code: Some(code), ..
        }
        | AegisError::CryptoError {
            code: Some(code), ..
        } if code == expected => Ok(()),
        other => Err(format!("unexpected error: {other:?}").into()),
    }
}

fn expect_err_code<T>(
    r: Result<T, AegisError>,
    expected: ErrorCode,
) -> Result<(), Box<dyn std::error::Error>> {
    let err = r.err().ok_or("expected error")?;
    assert_err_code(err, expected)
}

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

fn upload_three_tasks(
    c: &mut Console,
    request_ids: [u64; 3],
    passphrases: [&str; 3],
) -> Result<[String; 3], Box<dyn std::error::Error>> {
    let (a1, _priv_pem, _host_uuid) = build_test_artifact_bytes(passphrases[0])?;
    let (a2, _priv_pem2, _host_uuid2) = build_test_artifact_bytes(passphrases[1])?;
    let (a3, _priv_pem3, _host_uuid3) = build_test_artifact_bytes(passphrases[2])?;

    let t1 = upload_bytes_as_evidence(c, request_ids[0], a1.as_slice())?;
    std::thread::sleep(std::time::Duration::from_millis(2));
    let t2 = upload_bytes_as_evidence(c, request_ids[1], a2.as_slice())?;
    std::thread::sleep(std::time::Duration::from_millis(2));
    let t3 = upload_bytes_as_evidence(c, request_ids[2], a3.as_slice())?;
    Ok([t1, t2, t3])
}

#[test]
fn analyze_evidence_rejects_sequence0_without_meta() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut c) = temp_console()?;

    expect_err_code(
        c.analyze_evidence(AnalyzeEvidenceChunkInput {
            request_id: 1000,
            sequence_id: 0,
            is_last: true,
            bytes: vec![1, 2, 3],
            meta: None,
        }),
        ErrorCode::Console731,
    )?;
    Ok(())
}

#[test]
fn analyze_evidence_rejects_too_large_chunk() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut c) = temp_console()?;

    let bytes = vec![0u8; MAX_ARTIFACT_CHUNK_SIZE.saturating_add(1)];
    expect_err_code(
        c.analyze_evidence(AnalyzeEvidenceChunkInput {
            request_id: 1001,
            sequence_id: 0,
            is_last: true,
            bytes,
            meta: Some(AnalyzeEvidenceMeta {
                filename: Some("big.aes".to_string()),
                content_type: Some("application/octet-stream".to_string()),
            }),
        }),
        ErrorCode::Console731,
    )?;
    Ok(())
}

#[test]
fn analyze_evidence_out_of_order_marks_task_failed_and_deletes_file()
-> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw_seq")?;
    let (_dir, mut c) = temp_console()?;

    let out0 = c.analyze_evidence(AnalyzeEvidenceChunkInput {
        request_id: 2000,
        sequence_id: 0,
        is_last: false,
        bytes: artifact_bytes[0..64].to_vec(),
        meta: Some(AnalyzeEvidenceMeta {
            filename: Some("t.aes".to_string()),
            content_type: Some("application/octet-stream".to_string()),
        }),
    })?;

    expect_err_code(
        c.analyze_evidence(AnalyzeEvidenceChunkInput {
            request_id: 2000,
            sequence_id: 2,
            is_last: true,
            bytes: artifact_bytes[64..80].to_vec(),
            meta: None,
        }),
        ErrorCode::Console731,
    )?;

    let t = c.get_task(GetTaskInput {
        task_id: out0.task_id.clone(),
    })?;
    assert_eq!(t.task_id, out0.task_id);
    assert_eq!(t.status, TaskStatus::Failed);

    let case_path = t.case_path.ok_or("missing case_path")?;
    assert!(!std::path::Path::new(case_path.as_str()).exists());
    Ok(())
}

#[test]
fn analyze_evidence_rejects_chunks_after_finished_upload() -> Result<(), Box<dyn std::error::Error>>
{
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw_after")?;
    let (_dir, mut c) = temp_console()?;

    let task_id = upload_bytes_as_evidence(&mut c, 3000, artifact_bytes.as_slice())?;
    let t0 = c.get_task(GetTaskInput {
        task_id: task_id.clone(),
    })?;
    assert_eq!(t0.status, TaskStatus::Pending);
    let case_path0 = t0.case_path.ok_or("missing case_path")?;
    assert!(std::path::Path::new(case_path0.as_str()).exists());

    expect_err_code(
        c.analyze_evidence(AnalyzeEvidenceChunkInput {
            request_id: 3000,
            sequence_id: 999,
            is_last: true,
            bytes: vec![1, 2, 3],
            meta: None,
        }),
        ErrorCode::Console731,
    )?;

    let t1 = c.get_task(GetTaskInput { task_id })?;
    assert_eq!(t1.status, TaskStatus::Pending);
    let case_path1 = t1.case_path.ok_or("missing case_path")?;
    assert!(std::path::Path::new(case_path1.as_str()).exists());
    Ok(())
}

#[test]
fn analyze_evidence_rehydrates_restart_failed_task() -> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw_restart")?;
    let dir = tempfile::tempdir()?;

    let task_id = {
        let mut c1 = new_console_with_temp_persistence(&dir);
        let out = c1.analyze_evidence(AnalyzeEvidenceChunkInput {
            request_id: 4000,
            sequence_id: 0,
            is_last: false,
            bytes: artifact_bytes[0..64].to_vec(),
            meta: Some(AnalyzeEvidenceMeta {
                filename: Some("partial.aes".to_string()),
                content_type: Some("application/octet-stream".to_string()),
            }),
        })?;
        assert_eq!(out.status, TaskStatus::Uploading);
        assert_eq!(out.next_sequence_id, Some(1));
        out.task_id
    };

    let mut c2 = new_console_with_temp_persistence(&dir);
    let t = c2.get_task(GetTaskInput {
        task_id: task_id.clone(),
    })?;
    assert_eq!(t.status, TaskStatus::Failed);
    assert_eq!(t.next_sequence_id, Some(1));

    expect_err_code(
        c2.analyze_evidence(AnalyzeEvidenceChunkInput {
            request_id: 4000,
            sequence_id: 0,
            is_last: true,
            bytes: artifact_bytes[0..16].to_vec(),
            meta: Some(AnalyzeEvidenceMeta {
                filename: Some("retry.aes".to_string()),
                content_type: Some("application/octet-stream".to_string()),
            }),
        }),
        ErrorCode::Console731,
    )?;

    let out = c2.analyze_evidence(AnalyzeEvidenceChunkInput {
        request_id: 4000,
        sequence_id: 1,
        is_last: true,
        bytes: artifact_bytes[64..].to_vec(),
        meta: None,
    })?;
    assert_eq!(out.task_id, task_id);
    assert_eq!(out.status, TaskStatus::Pending);
    assert!(out.bytes_written.unwrap_or(0) > 64);
    assert_eq!(out.next_sequence_id, Some(2));
    Ok(())
}

#[test]
fn open_artifact_by_task_id_rejects_case_path_outside_cases_dir()
-> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw_out")?;
    let (dir, mut c) = temp_console()?;

    let _ = c.list_tasks(ListTasksInput { page: None })?;

    let outside_path = dir.path().join("outside.aes");
    std::fs::write(outside_path.as_path(), artifact_bytes.as_slice())?;

    let data_dir = dir.path().join("data");
    let db_path = data_dir.join("console.db");
    let outside_str = outside_path.display().to_string();

    let rt = tokio::runtime::Runtime::new()?;
    let pool = rt.block_on(async {
        let options = SqliteConnectOptions::new()
            .filename(db_path.as_path())
            .create_if_missing(true);
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
    })?;

    rt.block_on(async {
        sqlx::query(
            r"
INSERT INTO tasks (task_id, request_id, status, created_at_ms, updated_at_ms, case_path, bytes_written, error_message)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
",
        )
        .bind("evil_task")
        .bind(9999i64)
        .bind("pending")
        .bind(0i64)
        .bind(0i64)
        .bind(outside_str)
        .bind(i64::try_from(artifact_bytes.len()).unwrap_or(i64::MAX))
        .bind(Option::<String>::None)
        .execute(&pool)
        .await?;
        Ok::<(), sqlx::Error>(())
    })?;

    expect_err_code(
        c.open_artifact(OpenArtifactInput {
            source: Source::TaskId {
                task_id: "evil_task".to_string(),
            },
            decryption: Decryption::UserPassphrase {
                passphrase: "pw_out".to_string(),
            },
            options: OpenArtifactOptions {
                verify_hmac_if_present: true,
            },
        }),
        ErrorCode::Console733,
    )?;
    Ok(())
}

#[test]
fn list_tasks_pagination_returns_distinct_tasks() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut c) = temp_console()?;
    let [t1, t2, t3] = upload_three_tasks(&mut c, [5001, 5002, 5003], ["pw_p1", "pw_p2", "pw_p3"])?;

    let page1 = c.list_tasks(ListTasksInput {
        page: Some(Page {
            cursor: None,
            limit: Some(2),
        }),
    })?;
    assert_eq!(page1.tasks.len(), 2);
    let cursor = page1.next_cursor.clone().ok_or("missing next_cursor")?;

    let page2 = c.list_tasks(ListTasksInput {
        page: Some(Page {
            cursor: Some(cursor),
            limit: Some(2),
        }),
    })?;
    assert_eq!(page2.tasks.len(), 1);
    assert!(page2.next_cursor.is_none());

    let mut all: Vec<String> = Vec::new();
    all.extend(page1.tasks.iter().map(|t| t.task_id.clone()));
    all.extend(page2.tasks.iter().map(|t| t.task_id.clone()));
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 3);
    assert!(all.contains(&t1));
    assert!(all.contains(&t2));
    assert!(all.contains(&t3));
    Ok(())
}

#[test]
fn list_tasks_orders_by_created_at_desc() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut c) = temp_console()?;
    let [t1, t2, t3] = upload_three_tasks(&mut c, [5101, 5102, 5103], ["pw_o1", "pw_o2", "pw_o3"])?;

    let list = c.list_tasks(ListTasksInput { page: None })?;
    assert_eq!(list.tasks.len(), 3);
    assert_eq!(list.tasks[0].task_id, t3);
    assert_eq!(list.tasks[1].task_id, t2);
    assert_eq!(list.tasks[2].task_id, t1);
    assert!(list.tasks[0].created_at_ms >= list.tasks[1].created_at_ms);
    assert!(list.tasks[1].created_at_ms >= list.tasks[2].created_at_ms);
    Ok(())
}

#[test]
fn mark_task_done_with_error_sets_failed_status() -> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw_ai_fail")?;
    let (_dir, mut c) = temp_console()?;

    let task_id = upload_bytes_as_evidence(&mut c, 5200, artifact_bytes.as_slice())?;
    c.mark_task_running(task_id.as_str())?;
    c.mark_task_done_with_error(task_id.as_str(), "ai failed")?;

    let t = c.get_task(GetTaskInput { task_id })?;
    assert_eq!(t.status, TaskStatus::Failed);
    assert_eq!(t.error_message.as_deref(), Some("ai failed"));
    Ok(())
}

#[test]
fn open_artifact_with_passphrase_and_viewport_level0_connectivity()
-> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw1")?;
    let dir = tempfile::tempdir()?;
    let p = dir.path().join("t.aes");
    std::fs::write(p.as_path(), artifact_bytes.as_slice())?;

    let mut c = Console::new(ConsoleConfig::default());
    let out = c.open_artifact(OpenArtifactInput {
        source: Source::LocalPath {
            path: p.display().to_string(),
        },
        decryption: Decryption::UserPassphrase {
            passphrase: "pw1".to_string(),
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
fn viewport_bbox_is_processed_and_emits_warning_when_missing_coords()
-> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw_bbox")?;
    let dir = tempfile::tempdir()?;
    let p = dir.path().join("t_bbox.aes");
    std::fs::write(p.as_path(), artifact_bytes.as_slice())?;

    let mut c = Console::new(ConsoleConfig::default());
    let out = c.open_artifact(OpenArtifactInput {
        source: Source::LocalPath {
            path: p.display().to_string(),
        },
        decryption: Decryption::UserPassphrase {
            passphrase: "pw_bbox".to_string(),
        },
        options: OpenArtifactOptions::default(),
    })?;

    let v = c.get_graph_viewport(GetGraphViewportInput {
        case_id: out.case_id,
        level: ViewportLevel::L0,
        viewport_bbox: Some(BBox {
            x1: 0.0,
            y1: 0.0,
            x2: 1.0,
            y2: 1.0,
        }),
        risk_score_threshold: Some(0),
        center_node_id: None,
        page: None,
    })?;
    let warnings = v.warnings.unwrap_or_default();
    assert!(warnings.iter().any(|w| w.contains("viewport_bbox")));
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

    expect_err_code(
        c.get_graph_viewport(GetGraphViewportInput {
            case_id: out.case_id,
            level: ViewportLevel::L2,
            viewport_bbox: None,
            risk_score_threshold: None,
            center_node_id: None,
            page: Some(Page {
                cursor: None,
                limit: Some(10),
            }),
        }),
        ErrorCode::Console721,
    )?;
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
    expect_err_code(
        c.open_artifact(OpenArtifactInput {
            source: Source::LocalPath {
                path: p.display().to_string(),
            },
            decryption: Decryption::UserPassphrase {
                passphrase: "pw3".to_string(),
            },
            options: OpenArtifactOptions {
                verify_hmac_if_present: true,
            },
        }),
        ErrorCode::Crypto003,
    )?;
    Ok(())
}

#[test]
fn get_ai_insight_requires_loaded_case() -> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw_ai")?;
    let dir = tempfile::tempdir()?;
    let p = dir.path().join("t_ai.aes");
    std::fs::write(p.as_path(), artifact_bytes.as_slice())?;

    let mut c = Console::new(ConsoleConfig::default());
    let out = c.open_artifact(OpenArtifactInput {
        source: Source::LocalPath {
            path: p.display().to_string(),
        },
        decryption: Decryption::None,
        options: OpenArtifactOptions::default(),
    })?;

    expect_err_code(
        c.get_ai_insight(GetAiInsightInput {
            case_id: out.case_id,
            node_id: None,
            context: None,
        }),
        ErrorCode::Console711,
    )?;
    Ok(())
}

#[test]
fn analyze_evidence_then_open_artifact_by_task_id() -> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw4")?;
    let dir = tempfile::tempdir()?;
    let mut c = new_console_with_temp_persistence(&dir);

    let task_id = upload_bytes_as_evidence(&mut c, 42, artifact_bytes.as_slice())?;

    let t = c.get_task(GetTaskInput {
        task_id: task_id.clone(),
    })?;
    assert_eq!(t.task_id, task_id);
    assert!(matches!(t.status, TaskStatus::Pending));
    let expected_len = u64::try_from(artifact_bytes.len()).unwrap_or(u64::MAX);
    assert!(t.bytes_written.unwrap_or(0) >= expected_len);
    let case_path = t.case_path.ok_or("missing case_path")?;
    assert!(std::path::Path::new(case_path.as_str()).exists());

    let list = c.list_tasks(ListTasksInput { page: None })?;
    assert!(list.tasks.iter().any(|x| x.task_id == task_id));

    let out = c.open_artifact(OpenArtifactInput {
        source: Source::TaskId { task_id },
        decryption: Decryption::UserPassphrase {
            passphrase: "pw4".to_string(),
        },
        options: OpenArtifactOptions {
            verify_hmac_if_present: true,
        },
    })?;
    assert!(out.sealed);
    Ok(())
}

#[test]
fn restart_marks_uploading_task_failed() -> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw5")?;
    let dir = tempfile::tempdir()?;

    let task_id = {
        let mut c = new_console_with_temp_persistence(&dir);
        let out = c.analyze_evidence(AnalyzeEvidenceChunkInput {
            request_id: 7,
            sequence_id: 0,
            is_last: false,
            bytes: artifact_bytes[0..32].to_vec(),
            meta: Some(AnalyzeEvidenceMeta {
                filename: Some("partial.aes".to_string()),
                content_type: None,
            }),
        })?;
        assert_eq!(out.status, TaskStatus::Uploading);
        out.task_id
    };

    let mut c2 = new_console_with_temp_persistence(&dir);
    let t = c2.get_task(GetTaskInput { task_id })?;
    assert_eq!(t.status, TaskStatus::Failed);
    Ok(())
}

#[test]
fn analyze_evidence_rejects_duplicate_request_id() -> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw6")?;
    let dir = tempfile::tempdir()?;
    let mut c = new_console_with_temp_persistence(&dir);

    let _task_id = upload_bytes_as_evidence(&mut c, 9, artifact_bytes.as_slice())?;

    expect_err_code(
        c.analyze_evidence(AnalyzeEvidenceChunkInput {
            request_id: 9,
            sequence_id: 0,
            is_last: true,
            bytes: artifact_bytes[0..16].to_vec(),
            meta: Some(AnalyzeEvidenceMeta {
                filename: Some("dup.aes".to_string()),
                content_type: None,
            }),
        }),
        ErrorCode::Console731,
    )?;

    Ok(())
}

#[test]
fn open_artifact_by_task_id_rejects_failed_task() -> Result<(), Box<dyn std::error::Error>> {
    let (artifact_bytes, _priv_pem, _host_uuid) = build_test_artifact_bytes("pw7")?;
    let dir = tempfile::tempdir()?;

    let task_id = {
        let mut c = new_console_with_temp_persistence(&dir);
        let out = c.analyze_evidence(AnalyzeEvidenceChunkInput {
            request_id: 77,
            sequence_id: 0,
            is_last: false,
            bytes: artifact_bytes[0..32].to_vec(),
            meta: Some(AnalyzeEvidenceMeta {
                filename: Some("partial2.aes".to_string()),
                content_type: None,
            }),
        })?;
        assert_eq!(out.status, TaskStatus::Uploading);
        out.task_id
    };

    let mut c2 = new_console_with_temp_persistence(&dir);
    expect_err_code(
        c2.open_artifact(OpenArtifactInput {
            source: Source::TaskId {
                task_id: task_id.clone(),
            },
            decryption: Decryption::UserPassphrase {
                passphrase: "pw7".to_string(),
            },
            options: OpenArtifactOptions::default(),
        }),
        ErrorCode::Console731,
    )?;

    Ok(())
}
