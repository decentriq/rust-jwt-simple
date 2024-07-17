use anyhow::{ensure, Error};
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::claims::JWTClaims;
use crate::error::JWTError;
use crate::jwt_header::JWTHeader;
pub const MAX_HEADER_LENGTH: usize = 8192;

/// Utilities to get information about a JWT token
pub struct Token;

/// JWT token information useful before signature/tag verification
#[derive(Debug, Clone, Default)]
pub struct TokenMetadata {
    pub(crate) jwt_header: JWTHeader,
}

impl TokenMetadata {
    /// The JWT algorithm for this token ("alg")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party. Clients should ignore it and use
    /// the correct type of key directly.
    pub fn algorithm(&self) -> &str {
        &self.jwt_header.algorithm
    }

    /// The content type for this token ("cty")
    pub fn content_type(&self) -> Option<&str> {
        self.jwt_header.content_type.as_deref()
    }

    /// The key, or public key identifier for this token ("kid")
    pub fn key_id(&self) -> Option<&str> {
        self.jwt_header.key_id.as_deref()
    }

    /// The signature type for this token ("typ")
    pub fn signature_type(&self) -> Option<&str> {
        self.jwt_header.signature_type.as_deref()
    }

    /// The set of raw critical properties for this token ("crit")
    pub fn critical(&self) -> Option<&[String]> {
        self.jwt_header.critical.as_deref()
    }

    /// The certificate chain for this token ("x5c")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party.
    pub fn certificate_chain(&self) -> Option<&[String]> {
        self.jwt_header.certificate_chain.as_deref()
    }

    /// The key set URL for this token ("jku")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party. At the bare minimum, you should
    /// check that the URL belongs to the domain you expect.
    pub fn key_set_url(&self) -> Option<&str> {
        self.jwt_header.key_set_url.as_deref()
    }

    /// The public key for this token ("jwk")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party. At the bare minimum, you should
    /// check that it's in a set of public keys you already trust.
    pub fn public_key(&self) -> Option<&str> {
        self.jwt_header.public_key.as_deref()
    }

    /// The certificate URL for this token ("x5u")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party. At the bare minimum, you should
    /// check that the URL belongs to the domain you expect.
    pub fn certificate_url(&self) -> Option<&str> {
        self.jwt_header.certificate_url.as_deref()
    }

    /// URLsafe-base64-encoded SHA1 hash of the X.509 certificate for this token
    /// ("x5t") In practice, it can also be any string representing the
    /// public key. This information should not be trusted: it is
    /// unprotected and can be freely modified by a third party.
    pub fn certificate_sha1_thumbprint(&self) -> Option<&str> {
        self.jwt_header.certificate_sha1_thumbprint.as_deref()
    }

    /// URLsafe-base64-encoded SHA256 hash of the X.509 certificate for this
    /// token ("x5t#256") In practice, it can also be any string
    /// representing the public key. This information should not be trusted:
    /// it is unprotected and can be freely modified by a third party.
    pub fn certificate_sha256_thumbprint(&self) -> Option<&str> {
        self.jwt_header.certificate_sha256_thumbprint.as_deref()
    }
}

impl Token {
    pub(crate) fn build<AuthenticationOrSignatureFn, CustomClaims: Serialize + DeserializeOwned>(
        jwt_header: &JWTHeader,
        claims: JWTClaims<CustomClaims>,
        authentication_or_signature_fn: AuthenticationOrSignatureFn,
    ) -> Result<String, Error>
    where
        AuthenticationOrSignatureFn: FnOnce(&str) -> Result<Vec<u8>, Error>,
    {
        let jwt_header_json = serde_json::to_string(&jwt_header)?;
        let claims_json = serde_json::to_string(&claims)?;
        let authenticated = format!(
            "{}.{}",
            Base64UrlSafeNoPadding::encode_to_string(jwt_header_json)?,
            Base64UrlSafeNoPadding::encode_to_string(claims_json)?
        );
        let authentication_tag_or_signature = authentication_or_signature_fn(&authenticated)?;
        let mut token = authenticated;
        token.push('.');
        token.push_str(&Base64UrlSafeNoPadding::encode_to_string(
            authentication_tag_or_signature,
        )?);
        Ok(token)
    }

    /// Decode token information that can be usedful prior to signature/tag
    /// verification
    pub fn decode_metadata(token: &str) -> Result<TokenMetadata, Error> {
        let mut parts = token.split('.');
        let jwt_header_b64 = parts.next().ok_or(JWTError::CompactEncodingError)?;
        ensure!(
            jwt_header_b64.len() <= MAX_HEADER_LENGTH,
            JWTError::HeaderTooLarge
        );
        let jwt_header: JWTHeader = serde_json::from_slice(
            &Base64UrlSafeNoPadding::decode_to_vec(jwt_header_b64, None)?,
        )?;
        Ok(TokenMetadata { jwt_header })
    }
}
