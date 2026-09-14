use std::io::{BufRead, Read, Write};

use crate::Frame;

pub const MAX_FRAME_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("input/output error: {0}")]
    Io(#[from] std::io::Error),
    #[error("couldn't make out the frame: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("frame is longer than {MAX_FRAME_BYTES} bytes")]
    TooLarge,
}

pub fn write_frame<W: Write>(writer: &mut W, frame: &Frame) -> Result<(), CodecError> {
    let mut line = serde_json::to_vec(frame)?;
    line.push(b'\n');
    writer.write_all(&line)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame<R: BufRead>(reader: &mut R) -> Result<Option<Frame>, CodecError> {
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .by_ref()
            .take(MAX_FRAME_BYTES)
            .read_line(&mut line)?;
        if read == 0 {
            return Ok(None);
        }
        if read as u64 == MAX_FRAME_BYTES && !line.ends_with('\n') {
            return Err(CodecError::TooLarge);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return Ok(Some(serde_json::from_str(trimmed)?));
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use rosetun_config::ConnectionState;

    use super::*;
    use crate::{Event, Request};

    fn roundtrip(frame: &Frame) -> Frame {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, frame).expect("frame written");
        let mut reader = BufReader::new(buffer.as_slice());
        read_frame(&mut reader)
            .expect("the frame is read")
            .expect("the frame is not empty")
    }

    #[test]
    fn request_survives_roundtrip() {
        let frame = Frame::Request {
            id: 7,
            body: Request::Status,
        };
        assert_eq!(roundtrip(&frame), frame);
    }

    #[test]
    fn event_survives_roundtrip() {
        let frame = Frame::Event(Event::State(ConnectionState::Failed {
            reason: "handshake timeout".to_owned(),
        }));
        assert_eq!(roundtrip(&frame), frame);
    }

    #[test]
    fn stream_carries_several_frames() {
        let first = Frame::Request {
            id: 1,
            body: Request::Status,
        };
        let second = Frame::Request {
            id: 2,
            body: Request::Disconnect,
        };
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &first).unwrap();
        write_frame(&mut buffer, &second).unwrap();

        let mut reader = BufReader::new(buffer.as_slice());
        assert_eq!(read_frame(&mut reader).unwrap(), Some(first));
        assert_eq!(read_frame(&mut reader).unwrap(), Some(second));
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[test]
    fn blank_lines_are_skipped() {
        let mut buffer = b"\n\n".to_vec();
        write_frame(&mut buffer, &Frame::Request {
            id: 3,
            body: Request::Status,
        })
            .unwrap();
        let mut reader = BufReader::new(buffer.as_slice());
        assert!(matches!(
            read_frame(&mut reader).unwrap(),
            Some(Frame::Request { id: 3, .. })
        ));
    }
}