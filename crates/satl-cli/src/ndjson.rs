// SPDX-License-Identifier: BSD-2-Clause
//! Newline-delimited JSON, as the daemon streams it.
//!
//! Two endpoints answer a stream of one JSON object per line rather than a
//! JSON document: `POST /images/create` (pull progress, `\r\n`-terminated) and
//! `GET /events` (`\n`-terminated). Both arrive as arbitrary byte chunks that
//! do not respect message boundaries, so both need the same reassembly.

/// Split a byte stream into newline-delimited JSON messages.
#[derive(Debug, Default)]
pub struct LineSplitter {
    buffer: String,
}

impl LineSplitter {
    /// Feed one chunk; returns every complete line it finished.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buffer.push_str(&String::from_utf8_lossy(chunk));
        let mut lines = Vec::new();
        while let Some(index) = self.buffer.find('\n') {
            let line: String = self.buffer.drain(..=index).collect();
            let line = line.trim().to_owned();
            if !line.is_empty() {
                lines.push(line);
            }
        }
        lines
    }

    /// The trailing partial line, if the stream ended without a newline.
    pub fn finish(&mut self) -> Option<String> {
        let line = self.buffer.trim().to_owned();
        self.buffer.clear();
        if line.is_empty() { None } else { Some(line) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_lines_across_chunks() {
        let mut splitter = LineSplitter::default();
        assert!(splitter.push(b"{\"status\":\"Pull").is_empty());
        assert_eq!(
            splitter.push(b"ing\"}\n{\"status\":\"Done\"}\n"),
            vec![
                "{\"status\":\"Pulling\"}".to_owned(),
                "{\"status\":\"Done\"}".to_owned()
            ]
        );
        assert!(splitter.finish().is_none());
        assert!(splitter.push(b"{\"status\":\"tail\"}").is_empty());
        assert_eq!(splitter.finish(), Some("{\"status\":\"tail\"}".to_owned()));
    }
}
