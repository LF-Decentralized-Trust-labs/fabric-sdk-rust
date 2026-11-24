//! TLS trust for the REST clients (Fabric CA, osnadmin, operations).

use crate::error::BuilderError;

/// Parses the configured TLS CA PEM (one certificate or a bundle) into the
/// roots the client trusts exclusively. reqwest skips anything that is not
/// a certificate, so without this check a wrong file would pass `build` and
/// every request would then fail with an unknown-issuer error.
pub(crate) fn tls_roots(pem: &[u8]) -> Result<Vec<reqwest::Certificate>, BuilderError> {
    let certs = reqwest::Certificate::from_pem_bundle(pem)
        .map_err(|e| BuilderError::InvalidParameter(format!("TLS CA PEM: {e}")))?;
    if certs.is_empty() {
        return Err(BuilderError::InvalidParameter(
            "TLS CA PEM contains no certificate".into(),
        ));
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pem_without_certificate_is_rejected() {
        for pem in [
            &b"not a pem"[..],
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        ] {
            assert!(matches!(tls_roots(pem), Err(BuilderError::InvalidParameter(_))));
        }
    }

    #[test]
    fn every_certificate_of_a_bundle_is_kept() {
        let ca = include_bytes!("../../tests/resources/policy/org1-ca.pem");
        let bundle = [&ca[..], &ca[..]].concat();
        assert_eq!(tls_roots(ca).unwrap().len(), 1);
        assert_eq!(tls_roots(&bundle).unwrap().len(), 2);
    }
}
