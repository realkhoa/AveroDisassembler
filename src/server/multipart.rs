//! Minimal `multipart/form-data` parser (enough for `POST /api/scans`).
//!
//! Avoids pulling a full HTTP framework: Avero's API is local, single-user and only needs
//! to accept one file plus optional JSON options.

#[derive(Debug, Clone)]
pub struct MultipartPart {
    pub name: Option<String>,
    pub filename: Option<String>,
    pub body: Vec<u8>,
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| from + position)
}

fn param(header: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let start = header.find(&needle)? + needle.len();
    let rest = &header[start..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        let end = rest
            .find(|character: char| character == ';' || character.is_whitespace())
            .unwrap_or(rest.len());
        if end == 0 {
            None
        } else {
            Some(rest[..end].to_string())
        }
    }
}

/// Parse a multipart body. Returns a human-readable error for malformed input.
pub fn parse(content_type: &str, body: &[u8]) -> Result<Vec<MultipartPart>, String> {
    let boundary = param(content_type, "boundary").ok_or("missing multipart boundary")?;
    let delimiter = format!("--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut position = find(body, &delimiter, 0).ok_or("multipart delimiter not found")?;
    loop {
        position += delimiter.len();
        if body.get(position..position + 2) == Some(b"--") {
            break;
        }
        if body.get(position..position + 2) == Some(b"\r\n") {
            position += 2;
        }
        let headers_end =
            find(body, b"\r\n\r\n", position).ok_or("multipart headers not terminated")?;
        let headers = String::from_utf8_lossy(&body[position..headers_end]).to_string();
        let body_start = headers_end + 4;
        let next = find(body, &delimiter, body_start).ok_or("multipart body not terminated")?;
        let mut body_end = next;
        if body_end >= 2 && &body[body_end - 2..body_end] == b"\r\n" {
            body_end -= 2;
        }
        let mut name = None;
        let mut filename = None;
        for line in headers.split("\r\n") {
            if let Some((field, value)) = line.split_once(':') {
                if field.eq_ignore_ascii_case("content-disposition") {
                    name = param(value, "name");
                    filename = param(value, "filename");
                }
            }
        }
        parts.push(MultipartPart {
            name,
            filename,
            body: body[body_start..body_end].to_vec(),
        });
        position = next;
    }
    if parts.is_empty() {
        return Err("no multipart parts".to_string());
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_file_and_field_parts() {
        let boundary = "X-BOUNDARY";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sample.apk\"\r\nContent-Type: application/octet-stream\r\n\r\nAPKDATA\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"options\"\r\n\r\n{{\"min_string_len\":4}}\r\n--{boundary}--\r\n"
        )
        .into_bytes();
        let parts =
            parse(&format!("multipart/form-data; boundary={boundary}"), &body).expect("parse");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name.as_deref(), Some("file"));
        assert_eq!(parts[0].filename.as_deref(), Some("sample.apk"));
        assert_eq!(parts[0].body, b"APKDATA");
        assert_eq!(parts[1].name.as_deref(), Some("options"));
        assert_eq!(parts[1].body, b"{\"min_string_len\":4}");
    }

    #[test]
    fn rejects_missing_boundary() {
        assert!(parse("multipart/form-data", b"body").is_err());
    }
}
