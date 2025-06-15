//! Utility functions for the key-wallet library

/// Parse a hex character to its numeric value
pub(crate) fn parse_hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Parse a hex string into bytes
pub(crate) fn parse_hex_bytes(hex_str: &str, output: &mut [u8]) -> Result<(), &'static str> {
    if hex_str.len() != output.len() * 2 {
        return Err("invalid hex length");
    }

    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        let high = parse_hex_digit(chunk[0]).ok_or("invalid hex character")?;
        let low = parse_hex_digit(chunk[1]).ok_or("invalid hex character")?;
        output[i] = (high << 4) | low;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_digit() {
        assert_eq!(parse_hex_digit(b'0'), Some(0));
        assert_eq!(parse_hex_digit(b'9'), Some(9));
        assert_eq!(parse_hex_digit(b'a'), Some(10));
        assert_eq!(parse_hex_digit(b'f'), Some(15));
        assert_eq!(parse_hex_digit(b'A'), Some(10));
        assert_eq!(parse_hex_digit(b'F'), Some(15));
        assert_eq!(parse_hex_digit(b'g'), None);
        assert_eq!(parse_hex_digit(b'G'), None);
    }

    #[test]
    fn test_parse_hex_bytes() {
        let mut output = [0u8; 4];
        assert!(parse_hex_bytes("deadbeef", &mut output).is_ok());
        assert_eq!(output, [0xde, 0xad, 0xbe, 0xef]);

        let mut output = [0u8; 2];
        assert!(parse_hex_bytes("1234", &mut output).is_ok());
        assert_eq!(output, [0x12, 0x34]);

        // Test error cases
        let mut output = [0u8; 2];
        assert!(parse_hex_bytes("123", &mut output).is_err()); // Wrong length
        assert!(parse_hex_bytes("12345", &mut output).is_err()); // Wrong length
        assert!(parse_hex_bytes("12gg", &mut output).is_err()); // Invalid character
    }
}
