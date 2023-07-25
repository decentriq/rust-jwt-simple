#[derive(Debug, Clone, Default)]
pub struct KeyMetadata {
    pub(crate) key_set_url: Option<String>,
    pub(crate) public_key: Option<String>,
    pub(crate) certificate_url: Option<String>,
    pub(crate) certificate_sha1_thumbprint: Option<String>,
    pub(crate) certificate_sha256_thumbprint: Option<String>,
}

impl KeyMetadata {
    /// Add a key set URL to the metadata ("jku")
    pub fn with_key_set_url(mut self, key_set_url: impl ToString) -> Self {
        self.key_set_url = Some(key_set_url.to_string());
        self
    }

    /// Add a public key to the metadata ("jwk")
    pub fn with_public_key(mut self, public_key: impl ToString) -> Self {
        self.public_key = Some(public_key.to_string());
        self
    }

    /// Add a certificate URL to the metadata ("x5u")
    pub fn with_certificate_url(mut self, certificate_url: impl ToString) -> Self {
        self.certificate_url = Some(certificate_url.to_string());
        self
    }
}
