use anyhow::{anyhow, Error};
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;

pub struct Claims;

impl Claims {
    /// Create a new set of claims, with custom data, expiring in `valid_for`.
    pub fn with_custom_claims<CustomClaims: Serialize + DeserializeOwned>(
        custom_claims: CustomClaims,
        valid_for: Duration,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        let issue_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("Failed to generate issue time. Error {:?}", e))?;
        let expiration_time = issue_time.checked_add(valid_for).ok_or(anyhow!("Failed to generate expiration time"))?;
        Ok(JWTClaims {
            issued_at: Some(issue_time),
            expires_at: Some(expiration_time),
            invalid_before: Some(issue_time),
            audiences: None,
            issuer: None,
            jwt_id: None,
            subject: None,
            nonce: None,
            custom: custom_claims,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTClaims<CustomClaims> {
    /// Time the claims were created at
    #[serde(rename = "iat", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<Duration>,

    /// Time the claims expire at
    #[serde(rename = "exp", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Duration>,

    /// Time the claims will be invalid until
    #[serde(rename = "nbf", default, skip_serializing_if = "Option::is_none")]
    pub invalid_before: Option<Duration>,

    /// Issuer - This can be set to anything application-specific
    #[serde(rename = "iss", default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Subject - This can be set to anything application-specific
    #[serde(rename = "sub", default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// Audience
    #[serde(rename = "aud", default, skip_serializing_if = "Option::is_none")]
    pub audiences: Option<String>,

    /// JWT identifier
    ///
    /// That property was originally designed to avoid replay attacks, but
    /// keeping all previously sent JWT token IDs is unrealistic.
    ///
    /// Replay attacks are better addressed by keeping only the timestamp of the
    /// last valid token for a user, and rejecting anything older in future
    /// tokens.
    #[serde(rename = "jti", default, skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,

    /// Nonce
    #[serde(rename = "nonce", default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Custom (application-defined) claims
    #[serde(flatten)]
    pub custom: CustomClaims,
}
