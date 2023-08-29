use rustls::{
    server::{ClientCertVerified, ClientCertVerifier},
    CertRevocationListError, Certificate, CertificateError, DistinguishedName, RootCertStore,
};
use std::{sync::Arc, time::SystemTime};
use webpki::{DnsName, TlsClientTrustAnchors, TrustAnchor};

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

/// A `ClientCertVerifier` that will ensure that every client provides a trusted
/// certificate, check the the certificate is within a white list of domain names.
pub struct AllowWhitelistAuthenticatedClient {
    roots: Vec<Certificate>,
    subjects: Vec<DistinguishedName>,
    whitelist: Option<Vec<webpki::DnsName>>,
}

impl AllowWhitelistAuthenticatedClient {
    pub fn new(
        roots: Vec<Certificate>,
        whitelist: Option<Vec<DnsName>>,
    ) -> Result<Self, rustls::Error> {
        Ok(Self {
            subjects: trust_roots(&roots)?
                .into_iter()
                .map(|r| DistinguishedName::from(r.subject.to_vec()))
                .collect(),
            roots,
            whitelist,
        })
    }

    #[inline(always)]
    pub fn boxed(self) -> Arc<dyn ClientCertVerifier> {
        Arc::new(self)
    }
}

impl ClientCertVerifier for AllowWhitelistAuthenticatedClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        &self.subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        now: SystemTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let cert = webpki::EndEntityCert::try_from(end_entity.0.as_ref())?;
        let chain = intermediate_chain(intermediates);
        let trust_roots = trust_roots(&self.roots)?;
        let now = webpki::Time::try_from(now).map_err(|_| rustls::Error::FailedToGetCurrentTime)?;

        let trusted_anchors = TlsClientTrustAnchors(&trust_roots);

        cert.verify_is_valid_tls_client_cert(SUPPORTED_SIG_ALGS, &trusted_anchors, &chain, now)
            .map_err(pki_error)
            .map(|_| ClientCertVerified::assertion())?;

        if let Some(whitelist) = &self.whitelist {
            cert.verify_is_valid_for_at_least_one_dns_name(whitelist.iter().map(|o| o.as_ref()))
                .map_err(pki_error)
                .map(|_| ClientCertVerified::assertion())
        } else {
            Ok(ClientCertVerified::assertion())
        }
    }
}

fn intermediate_chain(intermediates: &[Certificate]) -> Vec<&[u8]> {
    intermediates.iter().map(|cert| cert.0.as_ref()).collect()
}

fn trust_roots(roots: &[Certificate]) -> Result<Vec<TrustAnchor>, rustls::Error> {
    let mut anchors = Vec::with_capacity(roots.len());
    for root in roots {
        let anchor = TrustAnchor::try_from_cert_der(&root.0).map_err(pki_error)?;
        anchors.push(anchor)
    }
    Ok(anchors)
}

fn pki_error(error: webpki::Error) -> rustls::Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime => CertificateError::BadEncoding.into(),
        CertNotValidYet => CertificateError::NotValidYet.into(),
        CertExpired | InvalidCertValidity => CertificateError::Expired.into(),
        UnknownIssuer => CertificateError::UnknownIssuer.into(),
        CertNotValidForName => CertificateError::NotValidForName.into(),
        CertRevoked => CertificateError::Revoked.into(),
        IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl.into(),

        InvalidSignatureForPublicKey
        | UnsupportedSignatureAlgorithm
        | UnsupportedSignatureAlgorithmForPublicKey => CertificateError::BadSignature.into(),

        InvalidCrlSignatureForPublicKey => CertRevocationListError::BadSignature.into(),

        _ => CertificateError::Other(Arc::new(error)).into(),
    }
}
