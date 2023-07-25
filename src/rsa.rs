use crate::claims::JWTClaims;
use crate::common::KeyMetadata;
use crate::jwt_header::JWTHeader;
use crate::token::Token;
use anyhow::Error;
use hmac_sha256::Hash as SHA256;
use rsa::pkcs1::DecodeRsaPrivateKey as _;
use rsa::pkcs8::DecodePrivateKey as _;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait RSAKeyPairLike {
    fn jwt_alg_name() -> &'static str;
    fn key_pair(&self) -> &RSAKeyPair;
    fn key_id(&self) -> &Option<String>;
    fn metadata(&self) -> &Option<KeyMetadata>;
    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error>;
    fn hash(message: &[u8]) -> Vec<u8>;
    fn padding_scheme(&self) -> rsa::PaddingScheme;

    fn sign<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        let jwt_header =
            JWTHeader::new(Self::jwt_alg_name().to_string(), self.key_id().clone()).with_metadata(self.metadata());
        Token::build(&jwt_header, claims, |authenticated| {
            let digest = Self::hash(authenticated.as_bytes());
            let mut rng = rand::thread_rng();
            let token = self.key_pair().as_ref().sign_blinded(&mut rng, self.padding_scheme(), &digest)?;
            Ok(token)
        })
    }
}

#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    rsa_sk: rsa::RsaPrivateKey,
    metadata: Option<KeyMetadata>,
}

impl RSAKeyPair {
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem.trim();
        let mut rsa_sk = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| format!("Failed to generate rsa_sk. Error {:?}", e))
            .map_err(anyhow::Error::msg)?;
        rsa_sk
            .validate()
            .map_err(|e| format!("Failed to validate rsa_sk. Error {:?}", e))
            .map_err(anyhow::Error::msg)?;
        rsa_sk
            .precompute()
            .map_err(|e| format!("Failed to precompute rsa_sk. Error {:?}", e))
            .map_err(anyhow::Error::msg)?;
        Ok(RSAKeyPair { rsa_sk, metadata: None })
    }
}

impl AsRef<rsa::RsaPrivateKey> for RSAKeyPair {
    fn as_ref(&self) -> &rsa::RsaPrivateKey {
        &self.rsa_sk
    }
}

#[derive(Debug, Clone)]
pub struct RS256KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

impl RS256KeyPair {
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(RS256KeyPair { key_pair: RSAKeyPair::from_pem(pem)?, key_id: None })
    }
}

impl RSAKeyPairLike for RS256KeyPair {
    fn jwt_alg_name() -> &'static str {
        "RS256"
    }

    fn key_pair(&self) -> &RSAKeyPair {
        &self.key_pair
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn metadata(&self) -> &Option<KeyMetadata> {
        &self.key_pair.metadata
    }

    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error> {
        self.key_pair.metadata = Some(metadata);
        Ok(())
    }

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA256::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign::<SHA256>()
    }
}
