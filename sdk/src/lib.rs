#![allow(missing_docs)]

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use common::error::AegisError;
use common::protocol::{ArtifactBuilder, Message};

#[derive(Debug, Clone)]
pub struct CompletedArtifact {
    pub request_id: u64,
    pub path: PathBuf,
    pub bytes_written: u64,
}

pub struct ArtifactUploadReceiver {
    out_dir: PathBuf,
    inflight: HashMap<u64, InflightArtifact>,
}

struct InflightArtifact {
    tmp_path: PathBuf,
    final_path: PathBuf,
    builder: ArtifactBuilder<BufWriter<File>>,
}

impl ArtifactUploadReceiver {
    pub fn new(out_dir: impl Into<PathBuf>) -> Self {
        Self {
            out_dir: out_dir.into(),
            inflight: HashMap::new(),
        }
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn push(&mut self, message: &Message) -> Result<Option<CompletedArtifact>, AegisError> {
        let request_id = message.header.request_id;

        if !self.inflight.contains_key(&request_id) {
            self.start_new(request_id)?;
        }

        let Some(inflight) = self.inflight.get_mut(&request_id) else {
            return Err(AegisError::ProtocolError {
                message: "Artifact receiver 状态异常：inflight 缺失".to_string(),
                code: None,
            });
        };
        inflight.builder.push(message)?;

        if !inflight.builder.is_finished() {
            return Ok(None);
        }

        let inflight = self
            .inflight
            .remove(&request_id)
            .ok_or(AegisError::ProtocolError {
                message: "Artifact receiver 状态异常：inflight 丢失".to_string(),
                code: None,
            })?;
        let bytes_written = inflight.builder.bytes_written();
        let mut writer = inflight.builder.into_inner();
        writer.flush().map_err(AegisError::IoError)?;
        drop(writer);

        std::fs::rename(inflight.tmp_path.as_path(), inflight.final_path.as_path())
            .map_err(AegisError::IoError)?;

        Ok(Some(CompletedArtifact {
            request_id,
            path: inflight.final_path,
            bytes_written,
        }))
    }

    #[allow(clippy::missing_errors_doc)]
    fn start_new(&mut self, request_id: u64) -> Result<(), AegisError> {
        if !self.out_dir.as_path().exists() {
            std::fs::create_dir_all(self.out_dir.as_path()).map_err(AegisError::IoError)?;
        }

        let tmp_name = format!("artifact_{request_id}.aes.part");
        let final_name = format!("artifact_{request_id}.aes");
        let tmp_path = self.out_dir.join(tmp_name);
        let final_path = self.out_dir.join(final_name);

        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp_path.as_path())
            .map_err(AegisError::IoError)?;

        let writer = BufWriter::new(file);
        let builder = ArtifactBuilder::new(request_id, writer);
        let prev = self.inflight.insert(
            request_id,
            InflightArtifact {
                tmp_path,
                final_path,
                builder,
            },
        );
        if prev.is_some() {
            return Err(AegisError::ProtocolError {
                message: "Artifact receiver 状态异常：request_id 重复".to_string(),
                code: None,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::protocol::{Chunker, DEFAULT_ARTIFACT_CHUNK_SIZE, MessageHeader, MessagePayload};

    #[test]
    fn receiver_writes_exact_bytes_in_order() -> Result<(), AegisError> {
        let temp = tempfile::tempdir().map_err(AegisError::IoError)?;
        let request_id = 42u64;
        let data: Vec<u8> = (0..(DEFAULT_ARTIFACT_CHUNK_SIZE + 123))
            .map(|i| u8::try_from(i % 251).unwrap_or_default())
            .collect();

        let chunker = Chunker::new(data.as_slice(), 128 * 1024, request_id)?;
        let mut rx = ArtifactUploadReceiver::new(temp.path());

        let mut completed = None;
        for msg in chunker {
            completed = rx.push(&msg?)?;
        }

        let done = completed.ok_or(AegisError::ProtocolError {
            message: "未完成 artifact".to_string(),
            code: None,
        })?;
        assert_eq!(done.request_id, request_id);
        let data_len = u64::try_from(data.len()).map_err(|_| AegisError::ProtocolError {
            message: "data.len() 超出 u64".to_string(),
            code: None,
        })?;
        assert_eq!(done.bytes_written, data_len);
        let bytes = std::fs::read(done.path.as_path()).map_err(AegisError::IoError)?;
        assert_eq!(bytes, data);
        Ok(())
    }

    #[test]
    fn receiver_allows_parallel_request_ids() -> Result<(), AegisError> {
        let temp = tempfile::tempdir().map_err(AegisError::IoError)?;
        let mut rx = ArtifactUploadReceiver::new(temp.path());

        let m1 = Message {
            header: MessageHeader {
                request_id: 1,
                timestamp: 0,
                command: common::protocol::Command::UploadArtifactChunk,
            },
            payload: MessagePayload::ArtifactChunk(common::protocol::ArtifactChunk {
                sequence_id: 0,
                is_last: false,
                bytes: b"a".to_vec(),
            }),
        };
        let m2 = Message {
            header: MessageHeader {
                request_id: 2,
                timestamp: 0,
                command: common::protocol::Command::UploadArtifactChunk,
            },
            payload: MessagePayload::ArtifactChunk(common::protocol::ArtifactChunk {
                sequence_id: 0,
                is_last: true,
                bytes: b"b".to_vec(),
            }),
        };

        assert!(rx.push(&m1)?.is_none());
        let completed = rx.push(&m2)?;
        assert!(completed.is_some());
        Ok(())
    }
}
