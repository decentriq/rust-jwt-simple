use ct_codecs::Base64UrlSafeNoPadding;
use ct_codecs::Decoder;
use rsa::PublicKey;
use serde::Deserialize;

use crate::jwt_header::JWTHeader;
use crate::token::TokenMetadata;

#[derive(Debug, Deserialize)]
pub struct Jwk {
    pub alg: String,
    pub kid: String,
    pub kty: String,
    pub e: Option<String>,
    pub n: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwk {
    pub fn public_key(&self) -> Result<ParsedPublicKey, anyhow::Error> {
        match self.kty.as_str() {
            "RSA" => {
                if let (Some(n), Some(e)) = (&self.n, &self.e) {
                    let n = rsa::BigUint::from_bytes_be(&ct_codecs::Base64UrlSafeNoPadding::decode_to_vec(n, None)?);
                    let e = rsa::BigUint::from_bytes_be(&ct_codecs::Base64UrlSafeNoPadding::decode_to_vec(e, None)?);
                    Ok(ParsedPublicKey::Rsa(rsa::RsaPublicKey::new(n, e)?))
                } else {
                    Err(anyhow::Error::msg(format!("Fields 'n' and 'e' not found on RSA JWT token")))
                }
            }
            _ => Err(anyhow::Error::msg(format!("Unsupported kty in JWT token: {}", self.kty))),
        }
    }
}

pub enum ParsedPublicKey {
    Rsa(rsa::RsaPublicKey),
}

impl ParsedPublicKey {
    // Verifies the signature of <header>.<claims>.<signature> and returns the claims part as serialized JSON
    pub fn verify_signature(&self, token: &str) -> Result<Vec<u8>, anyhow::Error> {
        let token_parts = token.split(".").collect::<Vec<_>>();
        if token_parts.len() != 3 {
            return Err(anyhow::Error::msg("Malformed token"));
        }

        let jwt_header: JWTHeader =
            serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(token_parts[0], None)?)?;

        let metadata = TokenMetadata { jwt_header };

        match metadata.algorithm() {
            "RS256" => {
                let authenticated = token_parts[.. 2].join(".");
                let signature = Base64UrlSafeNoPadding::decode_to_vec(&token_parts[2], None)?;
                #[allow(irrefutable_let_patterns)]
                if let ParsedPublicKey::Rsa(public_key) = self {
                    let padding = rsa::PaddingScheme::new_pkcs1v15_sign::<hmac_sha256::Hash>();
                    let hashed = hmac_sha256::Hash::hash(authenticated.as_bytes());
                    public_key.verify(padding, hashed.as_slice(), &signature)?;
                    Ok(Base64UrlSafeNoPadding::decode_to_vec(token_parts[1], None)?)
                } else {
                    Err(anyhow::Error::msg(format!("Expected RSA public key for algorithm: {}", metadata.algorithm())))
                }
            }
            _ => Err(anyhow::Error::msg(format!("Unsupported algorithm: {}", metadata.algorithm()))),
        }
    }
}
