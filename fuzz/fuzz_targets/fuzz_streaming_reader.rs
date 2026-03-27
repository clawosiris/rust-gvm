// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! P1 fuzz target for streaming XML reader with chunked input.
//!
//! Tests `XmlReader` by feeding arbitrary XML data in various chunk patterns
//! to exercise mid-element boundaries, mid-attribute splits, and edge cases.

#![no_main]

use arbitrary::Arbitrary;
use gvm_protocol::XmlReader;
use libfuzzer_sys::fuzz_target;

/// Chunking strategy for feeding data to the reader.
#[derive(Debug, Clone, Arbitrary)]
enum ChunkStrategy {
    /// Feed all data at once
    SingleChunk,
    /// Feed one byte at a time
    ByteByByte,
    /// Feed in fixed-size chunks
    FixedSize(#[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(1..=64))] usize),
    /// Feed in random-sized chunks defined by split points
    RandomSplits(
        #[arbitrary(with = |u: &mut arbitrary::Unstructured| -> arbitrary::Result<Vec<u8>> {
            let len = u.int_in_range(0..=16)?;
            let mut splits: Vec<u8> = (0..len).map(|_| u.arbitrary()).collect::<Result<_, _>>()?;
            splits.sort();
            splits.dedup();
            Ok(splits)
        })]
        Vec<u8>,
    ),
}

#[derive(Debug, Clone, Arbitrary)]
struct ChunkedXmlInput {
    /// Raw XML data to feed
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| -> arbitrary::Result<Vec<u8>> {
        let len = u.int_in_range(0..=1024)?;
        u.bytes(len).map(|b| b.to_vec())
    })]
    data: Vec<u8>,
    /// How to chunk the data
    strategy: ChunkStrategy,
    /// Optional max buffer limit to test overflow handling
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| -> arbitrary::Result<Option<usize>> {
        if u.ratio(1, 10)? {
            Ok(Some(u.int_in_range(8..=2048)?))
        } else {
            Ok(None)
        }
    })]
    max_buffer: Option<usize>,
}

impl ChunkedXmlInput {
    fn chunk_boundaries(&self) -> Vec<usize> {
        let len = self.data.len();
        if len == 0 {
            return vec![0];
        }

        match &self.strategy {
            ChunkStrategy::SingleChunk => vec![len],
            ChunkStrategy::ByteByByte => (1..=len).collect(),
            ChunkStrategy::FixedSize(size) => {
                let mut boundaries = Vec::new();
                let mut pos = 0;
                while pos < len {
                    pos = (pos + size).min(len);
                    boundaries.push(pos);
                }
                boundaries
            }
            ChunkStrategy::RandomSplits(splits) => {
                let mut boundaries: Vec<usize> = splits
                    .iter()
                    .map(|&s| (s as usize).min(len))
                    .filter(|&s| s > 0 && s < len)
                    .collect();
                boundaries.sort();
                boundaries.dedup();
                boundaries.push(len);
                boundaries
            }
        }
    }
}

fuzz_target!(|input: ChunkedXmlInput| {
    // Create reader with optional buffer limit
    let mut reader = match input.max_buffer {
        Some(max) => XmlReader::with_max_buffer(max),
        None => XmlReader::new(),
    };

    let boundaries = input.chunk_boundaries();
    let mut prev = 0;

    for boundary in boundaries {
        if boundary > input.data.len() {
            break;
        }

        let chunk = &input.data[prev..boundary];
        prev = boundary;

        // Feed chunk — errors are expected for malformed XML or buffer overflow
        match reader.feed(chunk) {
            Ok(()) => {
                // Check completion state — should never panic
                let _ = reader.is_complete();
            }
            Err(_) => {
                // Error is acceptable (malformed XML, buffer overflow, etc.)
                // Just ensure we don't panic
                break;
            }
        }

        // If complete, verify we can access data without panic
        if reader.is_complete() {
            let _ = reader.data();
            break;
        }
    }

    // Final state checks — should never panic
    let _ = reader.is_complete();
    let _ = reader.data();

    // Test reset doesn't panic
    reader.reset();
    assert!(!reader.is_complete());
    assert!(reader.data().is_empty());
});
