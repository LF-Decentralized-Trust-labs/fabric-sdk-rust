//! Reading REST response bodies with an upper bound.

/// Largest response body the REST clients read: Fabric's default gRPC
/// message limit (100 MiB). Fabric CA, osnadmin and operations answers are
/// far smaller, so anything bigger is a misbehaving server.
pub(crate) const MAX_RESPONSE_SIZE: usize = 100 * 1024 * 1024;

/// Reads the body of `response`, failing instead of buffering more than
/// [`MAX_RESPONSE_SIZE`] bytes. The error is a message for the caller's
/// own error type.
pub(crate) async fn read_body(response: reqwest::Response) -> Result<Vec<u8>, String> {
    read_body_limited(response, MAX_RESPONSE_SIZE).await
}

#[cfg(not(target_arch = "wasm32"))]
async fn read_body_limited(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    check_announced_length(response.content_length(), limit)?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| error_chain(&e))? {
        if body.len() + chunk.len() > limit {
            return Err(too_large(limit));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The browser's fetch has no chunked reads in reqwest; check the announced
/// length before reading and the real one after.
#[cfg(target_arch = "wasm32")]
async fn read_body_limited(response: reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    check_announced_length(response.content_length(), limit)?;
    let body = response.bytes().await.map_err(|e| error_chain(&e))?;
    if body.len() > limit {
        return Err(too_large(limit));
    }
    Ok(body.to_vec())
}

fn check_announced_length(length: Option<u64>, limit: usize) -> Result<(), String> {
    match length {
        Some(length) if length > limit as u64 => Err(too_large(limit)),
        _ => Ok(()),
    }
}

/// The error with all its causes, as the clients report transport errors:
/// reqwest's own message alone ("error decoding response body") hides why.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut message = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

fn too_large(limit: usize) -> String {
    format!("response body larger than {limit} bytes")
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn response(body: &'static str, announce_length: bool) -> reqwest::Response {
        let mut builder = tonic::codegen::http::Response::builder().status(200);
        if !announce_length {
            // Chunked: no Content-Length for the client to check up front.
            builder = builder.header("transfer-encoding", "chunked");
        }
        reqwest::Response::from(builder.body(body).unwrap())
    }

    #[test]
    fn error_chain_lists_every_cause() {
        let error = ChainedError(std::io::Error::other("connection reset"));
        assert_eq!(error_chain(&error), "body read failed: connection reset");
    }

    #[derive(Debug)]
    struct ChainedError(std::io::Error);
    impl std::fmt::Display for ChainedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("body read failed")
        }
    }
    impl std::error::Error for ChainedError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[tokio::test]
    async fn bodies_above_the_limit_are_refused() {
        assert_eq!(read_body_limited(response("12345", true), 5).await.unwrap(), b"12345");
        assert!(read_body_limited(response("123456", true), 5).await.is_err());
        assert!(read_body_limited(response("123456", false), 5).await.is_err());
    }
}
