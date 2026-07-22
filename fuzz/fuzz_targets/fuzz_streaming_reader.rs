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
    fn chunk_boundaries(&self, len: usize) -> Vec<usize> {
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

#[derive(Debug, PartialEq, Eq)]
enum ReaderOutcome {
    Error,
    Parsed {
        frames: Vec<Vec<u8>>,
        remainder: Vec<u8>,
    },
}

fn new_reader(max_buffer: Option<usize>) -> XmlReader {
    match max_buffer {
        Some(max) => XmlReader::with_max_buffer(max),
        None => XmlReader::new(),
    }
}

fn run_aggregate_reader(input: &ChunkedXmlInput, boundaries: &[usize]) -> ReaderOutcome {
    let mut reader = new_reader(input.max_buffer);
    let mut previous = 0;

    for &boundary in boundaries {
        if boundary > input.data.len() || boundary < previous {
            return ReaderOutcome::Error;
        }

        if reader.feed(&input.data[previous..boundary]).is_err() {
            return ReaderOutcome::Error;
        }
        previous = boundary;

        if let Some(frame_len) = reader.frame_len() {
            assert!(frame_len <= reader.data().len());
            assert_eq!(reader.frame().map(<[u8]>::len), Some(frame_len));
            assert_eq!(
                reader.tail().map(<[u8]>::len),
                Some(reader.data().len() - frame_len)
            );
        }
    }

    let mut frames = Vec::new();
    loop {
        match reader.take_frame() {
            Ok(Some(frame)) => {
                assert!(!frame.is_empty());
                frames.push(frame);
            }
            Ok(None) => break,
            Err(_) => return ReaderOutcome::Error,
        }
    }

    let remainder = reader.data().to_vec();
    let mut reconstructed = frames.concat();
    reconstructed.extend_from_slice(&remainder);
    assert_eq!(reconstructed, input.data);

    reader.reset();
    assert!(!reader.is_complete());
    assert!(reader.data().is_empty());

    ReaderOutcome::Parsed { frames, remainder }
}

fn run_frame_reader(data: &[u8], max_buffer: Option<usize>, boundaries: &[usize]) -> ReaderOutcome {
    let mut reader = new_reader(max_buffer);
    let mut frames = Vec::new();
    let mut previous = 0;

    for &boundary in boundaries {
        if boundary > data.len() || boundary < previous {
            return ReaderOutcome::Error;
        }

        let mut offset = previous;
        while offset < boundary {
            let available = boundary - offset;
            let consumed = match reader.feed_frame(&data[offset..boundary]) {
                Ok(consumed) => consumed,
                Err(_) => return ReaderOutcome::Error,
            };
            assert!(consumed <= available);
            offset += consumed;

            match reader.take_frame() {
                Ok(Some(frame)) => {
                    assert!(!frame.is_empty());
                    assert!(consumed > 0, "a completed frame must make progress");
                    frames.push(frame);
                }
                Ok(None) => {
                    assert_eq!(
                        offset, boundary,
                        "an incomplete frame must consume the available chunk"
                    );
                }
                Err(_) => return ReaderOutcome::Error,
            }
        }
        previous = boundary;
    }

    let remainder = reader.data().to_vec();
    let mut reconstructed = frames.concat();
    reconstructed.extend_from_slice(&remainder);
    assert_eq!(reconstructed, data);

    ReaderOutcome::Parsed { frames, remainder }
}

fn well_formed_frames(seed: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    if seed.is_empty() {
        return b"<frame/>".to_vec();
    }

    let mut xml = Vec::with_capacity(seed.len().saturating_mul(2).saturating_add(512));
    for chunk in seed.chunks(32) {
        xml.extend_from_slice(b"<frame>");
        for byte in chunk {
            xml.push(HEX[(byte >> 4) as usize]);
            xml.push(HEX[(byte & 0x0f) as usize]);
        }
        xml.extend_from_slice(b"</frame>");
    }
    xml
}

fuzz_target!(|input: ChunkedXmlInput| {
    let raw_boundaries = input.chunk_boundaries(input.data.len());

    // Arbitrary malformed input is a no-panic, bounds, and reconstruction
    // exercise. A streaming parser may reject an incomplete malformed prefix
    // earlier than a single-chunk parser, so error timing is not compared.
    let _ = run_aggregate_reader(&input, &raw_boundaries);
    let _ = run_aggregate_reader(&input, &[input.data.len()]);
    let _ = run_frame_reader(&input.data, input.max_buffer, &raw_boundaries);
    let _ = run_frame_reader(&input.data, input.max_buffer, &[input.data.len()]);

    // For complete well-formed frame sequences, production `feed_frame`
    // behavior must be independent of transport chunk boundaries.
    let valid = well_formed_frames(&input.data);
    let valid_boundaries = input.chunk_boundaries(valid.len());
    let chunked = run_frame_reader(&valid, input.max_buffer, &valid_boundaries);
    let single = run_frame_reader(&valid, input.max_buffer, &[valid.len()]);

    assert_eq!(chunked, single);
});
