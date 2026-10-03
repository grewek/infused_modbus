// Compresses/decompresses a device-description TOML source for the planned
// FC43-manifest + bulk-FC20-transfer fallback (CLAUDE.md's "Planned: grow
// FC43's device-description transfer capacity past its current ~31KB
// ceiling", Thread A4) — not yet wired into the server's actual startup
// sequence or into any FC43/FC20 dispatch; that's Thread A5/A6/A7. This
// module is the standalone, independently-testable capability those steps
// will call.
//
// `miniz_oxide` (DEFLATE), used directly rather than through `flate2` — see
// CLAUDE.md's "Compression crate choice" for the full comparison against
// `ruzstd`/Zstandard. This project only ever compresses one whole in-memory
// TOML string at startup, never streams, so `flate2`'s `Read`/`Write`
// adapter layer (and its own extra `crc32fast` dependency) buys nothing
// here.
//
// `compress_toml_source` is real CPU work, meant to be called exactly once
// at server startup and its result cached for the process's whole lifetime
// (the TOML never changes afterward) — unlike
// `device_identification::build_objects`, which is cheap enough to redo on
// every FC43 request.

use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::{DecompressError, decompress_to_vec_with_limit};

// Best ratio, not best speed — this runs once per server process lifetime,
// so the usual speed/ratio tradeoff a per-request codec would need doesn't
// apply; what matters here is minimizing FC20 round trips on the wire.
const COMPRESSION_LEVEL: u8 = 10;

// A device description this large would already be ~4.5x past the
// "absolute theoretical max" scenario CLAUDE.md's FC43-capacity sizing
// analysis worked out (full 65536-point tables on all four Modbus data
// types, one device, uncompressed) — generous enough for any real
// deployment, bounded enough that a corrupted or malicious compressed blob
// can't make a decompressing peer allocate unbounded memory (a classic
// "zip bomb" — see this project's standing harden-against-malicious-peers
// convention).
const MAX_DECOMPRESSED_LEN: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum DecompressTomlSourceError {
    Decompress(DecompressError),
    InvalidUtf8(std::string::FromUtf8Error),
}

impl std::fmt::Display for DecompressTomlSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecompressTomlSourceError::Decompress(error) => {
                write!(formatter, "failed to decompress: {error:?}")
            }
            DecompressTomlSourceError::InvalidUtf8(error) => {
                write!(formatter, "decompressed bytes are not valid UTF-8: {error}")
            }
        }
    }
}

impl std::error::Error for DecompressTomlSourceError {}

pub fn compress_toml_source(toml_source: &str) -> Vec<u8> {
    compress_to_vec(toml_source.as_bytes(), COMPRESSION_LEVEL)
}

pub fn decompress_toml_source(compressed: &[u8]) -> Result<String, DecompressTomlSourceError> {
    let decompressed = decompress_to_vec_with_limit(compressed, MAX_DECOMPRESSED_LEN)
        .map_err(DecompressTomlSourceError::Decompress)?;
    String::from_utf8(decompressed).map_err(DecompressTomlSourceError::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_small_toml_source() {
        let toml_source = "name = \"Stop_Process\"\naddress = 40002\n";
        let compressed = compress_toml_source(toml_source);
        assert_eq!(decompress_toml_source(&compressed).unwrap(), toml_source);
    }

    #[test]
    fn round_trips_an_empty_source() {
        let compressed = compress_toml_source("");
        assert_eq!(decompress_toml_source(&compressed).unwrap(), "");
    }

    #[test]
    fn compresses_repetitive_source_meaningfully() {
        // Mirrors the "synthetic 200-point/machine file" shape measured in
        // CLAUDE.md's FC43-capacity sizing session (14.1x there, via
        // Python's gzip) -- not asserting an exact ratio here (DEFLATE
        // parameters/implementation details could shift it slightly), just
        // that real compression is actually happening, not a no-op.
        let toml_source = "[[machines.registers.entries]]\nname = \"X\"\naddress = 1\n".repeat(200);
        let compressed = compress_toml_source(&toml_source);
        assert!(compressed.len() < toml_source.len() / 4);
    }

    #[test]
    fn decompress_rejects_garbage_bytes() {
        assert!(matches!(
            decompress_toml_source(&[0xFF, 0xFE, 0x00, 0x01]),
            Err(DecompressTomlSourceError::Decompress(_))
        ));
    }

    #[test]
    fn decompress_rejects_valid_deflate_that_is_not_utf8() {
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        let compressed = compress_to_vec(&invalid_utf8, COMPRESSION_LEVEL);
        assert!(matches!(
            decompress_toml_source(&compressed),
            Err(DecompressTomlSourceError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn decompress_rejects_output_exceeding_the_size_limit() {
        let huge_toml_source = "x".repeat(MAX_DECOMPRESSED_LEN + 1);
        let compressed = compress_toml_source(&huge_toml_source);
        assert!(matches!(
            decompress_toml_source(&compressed),
            Err(DecompressTomlSourceError::Decompress(_))
        ));
    }
}
