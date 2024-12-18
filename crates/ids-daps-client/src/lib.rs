//! # ids-daps
//!
//! The `ids-daps` crate provides a rust client for the Dynamic Attribute Token Service (DAPS) of
//! the Reference Architecture Model 4 (RAM 4) of the International Data Spaces Association (IDSA).
//!
//! ## Usage
//!
//! ```
//! use ids_daps_client::{config::DapsConfigBuilder, DapsClient, ReqwestDapsClient};
//! # use testcontainers::runners::AsyncRunner;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! #   // Let's start a DAPS for test purposes
//! #   let image = testcontainers::GenericImage::new("ghcr.io/ids-basecamp/daps", "test");
//! #   let container = image
//! #       .with_exposed_port(4567.into()) // will default to TCP protocol
//! #       .with_wait_for(testcontainers::core::WaitFor::message_on_stdout(
//! #           "Listening on 0.0.0.0:4567, CTRL+C to stop",
//! #       ))
//! #       .start()
//! #       .await
//! #       .expect("Failed to start DAPS container");
//! #
//! #   // Retrieve the host port mapped to the container's internal port 4567
//! #   let host = container.get_host().await.expect("Failed to get host");
//! #   let host_port = container
//! #       .get_host_port_ipv4(4567)
//! #       .await
//! #       .expect("Failed to get port");
//! #
//! #   // Construct URLs using the dynamically retrieved host and host_port
//! #   let certs_url = format!("http://{host}:{host_port}/jwks.json");
//! #   let token_url = format!("http://{host}:{host_port}/token");
//! #
//!     // Create a DAPS client configuration
//!     let config = DapsConfigBuilder::default()
//!         .certs_url(certs_url)
//!         .token_url(token_url)
//!         .private_key(std::path::Path::new("./testdata/connector-certificate.p12"))
//!         .private_key_password(Some(std::borrow::Cow::from("Password1")))
//!         .scope(std::borrow::Cow::from("idsc:IDS_CONNECTORS_ALL"))
//!         .certs_cache_ttl(1_u64)
//!         .build()
//!         .expect("Failed to build DAPS-Config");
//!
//!     // Create DAPS client
//!     let client: ReqwestDapsClient = DapsClient::new(&config);
//!
//!     // Request a DAT token
//!     let dat = client.request_dat().await?;
//!     println!("DAT Token: {dat}");
//!
//!     // Validate the DAT token
//!     if client.validate_dat(&dat).await.is_ok() {
//!         println!("Validation successful");
//!     }
//!
//!     Ok(())
//! }

#![deny(unsafe_code, rust_2018_idioms, clippy::unwrap_used)]
#![warn(rust_2024_compatibility, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

mod cache;
pub mod config;
mod http_client;

/// The type of the audience field in the DAT token. It can be a single string or a list of strings.
#[derive(Debug, serde::Deserialize, Clone)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, serde::Serialize, Clone)]
struct TokenClaims {
    #[serde(rename = "@type")]
    type_: String,
    #[serde(rename = "@context")]
    context_: String,
    iss: String,
    sub: String,
    id: String,
    jti: String,
    aud: String,
    iat: i64,
    exp: i64,
    nbf: i64,
}

/// Token response from the DAPS.
#[derive(Debug, serde::Deserialize, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: Option<String>,
}

/// Claims within the DAT token.
#[derive(Debug, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct DatClaims {
    #[serde(rename = "@type")]
    pub type_: String,
    #[serde(rename = "@context")]
    pub context_: String,
    pub referring_connector: String,
    pub security_profile: String,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    #[serde(rename = "exp")]
    pub expires_at: i64,
    #[serde(rename = "nbf")]
    pub not_before: i64,
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(rename = "aud")]
    pub audience: Audience,
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "jti")]
    pub jwt_id: String,
}

#[derive(thiserror::Error, Debug)]
pub enum DapsError {
    #[error("http client error: {0}")]
    DapsHttpClient(#[from] http_client::DapsHttpClientError),
    #[error("jwt error")]
    InvalidToken,
    #[error("cache error: {0}")]
    CacheError(#[from] cache::CertificatesCacheError),
}

/// An alias for the DAPS client using the Reqwest HTTP client.
pub type ReqwestDapsClient = DapsClient<http_client::reqwest_client::ReqwestDapsClient>;

/// The main struct of this crate. It provides the functionality to request and validate DAT tokens
/// from a DAPS.
#[must_use]
pub struct DapsClient<C> {
    /// The HTTP client to use for requests. It is generic over the actual implementation.
    client: C,
    /// The subject of the client.
    sub: String,
    /// The URL for the request of the certificates for validation.
    certs_url: String,
    /// The URL for the request of a DAPS token.
    token_url: String,
    /// The scope for the DAPS token.
    scope: String,
    /// The encoding key for the JWT.
    encoding_key: jsonwebtoken::EncodingKey,
    /// A cache for the certificates of the DAPS.
    certs_cache: cache::CertificatesCache,
}

impl<C> DapsClient<C>
where
    C: http_client::DapsClientRequest,
{
    /// Creates a new DAPS client based on the given configuration.
    pub fn new(config: &config::DapsConfig<'_>) -> Self {
        let cert_util = ids_daps_cert::CertUtil::load_certificate(
            config.private_key.as_ref(),
            config.private_key_password.as_deref().unwrap_or(""),
        )
        .expect("Certificate not found or could not be read");

        Self::from_cert_util(
            &cert_util,
            config.scope.as_ref(),
            config.certs_url.as_ref(),
            config.token_url.as_ref(),
            config.certs_cache_ttl
        )
    }

    /**
     * Creates a new DAPS client based on the given configuration with a given `cert_util`.
     * This is a small optimization for users, which already have and instance of
     * `ids_daps_cert::CertUtil` to not read the certificate twice from the filesystem.
     */
    pub fn from_cert_util(cert_util: &ids_daps_cert::CertUtil, scope: &str, certs_url: &str, token_url: &str, certs_cache_ttl: u64) -> Self {
        let ski_aki = cert_util
            .ski_aki()
            .expect("Extracting SKI:AKI failed");
        let private_key = cert_util
            .private_key_der()
            .expect("Extracting DER private key failed");

        // Use private key to create the encoding key
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_der(private_key.as_ref());
        Self {
            client: C::default(),
            sub: ski_aki.to_string(),
            scope: scope.to_string(),
            certs_url: certs_url.to_string(),
            token_url: token_url.to_string(),
            encoding_key,
            certs_cache: cache::CertificatesCache::new(std::time::Duration::from_secs(
                certs_cache_ttl,
            )),
        }
    }

    /// Validates a DAT token against the DAPS.
    pub async fn validate_dat(
        &self,
        token: &str,
    ) -> Result<jsonwebtoken::TokenData<DatClaims>, DapsError> {
        // Get JWKS from DAPS
        let jwks = self.get_certs().await?;

        // Set up validation configuration
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&["idsc:IDS_CONNECTORS_ALL"]);
        validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);

        // Decode against all keys
        let validation_results: Vec<jsonwebtoken::TokenData<_>> = jwks
            .keys
            .iter()
            .filter_map(|jwk| {
                if let Ok(jwk) = jsonwebtoken::DecodingKey::from_jwk(jwk) {
                    let result = jsonwebtoken::decode(token, &jwk, &validation);
                    tracing::debug!("Validation result: {:?}", result);
                    result.ok()
                } else {
                    None
                }
            })
            .collect();

        // Return first positive validation result
        validation_results
            .first()
            .ok_or(DapsError::InvalidToken)
            .cloned()
    }

    /// Requests a DAT token from the DAPS.
    pub async fn request_dat(&self) -> Result<String, DapsError> {
        // Get the current timestamp for the claims
        let now = chrono::Utc::now();
        let now_secs = now.timestamp();

        // Create a JWT for the client assertion
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let claims = TokenClaims {
            context_: "https://w3id.org/idsa/contexts/context.jsonld".to_string(),
            type_: "ids:DatRequestToken".to_string(),
            jti: uuid::Uuid::new_v4().hyphenated().to_string(),
            iss: self.sub.to_string(),
            sub: self.sub.to_string(),
            id: self.sub.to_string(),
            aud: self.scope.to_string(),
            iat: now_secs,
            exp: now_secs + 3600,
            nbf: now_secs,
        };
        // Encode token
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .expect("Token signing failed. There must be something wrong with the private key.");

        tracing::debug!("Issued TokenRequest (requestDAT): {}", token);

        let response = self
            .client
            .request_token(
                self.token_url.as_ref(),
                &[
                    ("grant_type", "client_credentials"),
                    ("scope", "idsc:IDS_CONNECTOR_ATTRIBUTES_ALL"),
                    (
                        "client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    ),
                    ("client_assertion", &token),
                ],
            )
            .await?;

        Ok(response.access_token)
    }

    /// Returns the `jsonwebtoken::jwk::JwkSet` either from the DAPS or from the cache.
    pub async fn get_jwks(&self) -> Result<jsonwebtoken::jwk::JwkSet, DapsError> {
        self.get_certs().await
    }

    /// Updates the certificate cache with the Certificates requested from the DAPS.
    async fn update_cert_cache(&self) -> Result<jsonwebtoken::jwk::JwkSet, DapsError> {
        let jwks = self.client.get_certs(self.certs_url.as_ref()).await?;
        self.certs_cache
            .update(jwks.clone())
            .await
            .map_err(DapsError::from)
    }

    /// Returns the certificates from the cache or updates the cache if it is outdated.
    async fn get_certs(&self) -> Result<jsonwebtoken::jwk::JwkSet, DapsError> {
        tracing::debug!("Checking cache...");

        match self.certs_cache.get().await {
            Ok(cert) => {
                tracing::debug!("Cache is up-to-date");
                Ok(cert)
            }
            Err(cache::CertificatesCacheError::Outdated) => {
                tracing::info!("Cache is outdated, updating...");
                self.update_cert_cache().await
            }
            Err(cache::CertificatesCacheError::Empty) => {
                tracing::info!("Cache is empty, updating...");
                self.update_cert_cache().await
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn integration_test() {
        use testcontainers::runners::AsyncRunner;

        // Setting up logger to debug issues
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("ids_daps=DEBUG"))
            .init();

        // Starting the test DAPS
        let image = testcontainers::GenericImage::new("ghcr.io/ids-basecamp/daps", "test");
        let container = image
            .with_exposed_port(4567.into()) // will default to TCP protocol
            .with_wait_for(testcontainers::core::WaitFor::message_on_stdout(
                "Listening on 0.0.0.0:4567, CTRL+C to stop",
            ))
            .start()
            .await
            .expect("Failed to start DAPS container. Is Docker running?");

        // Retrieve the host port mapped to the container's internal port 4567
        let host = container.get_host().await.expect("Failed to get host");
        let host_port = container
            .get_host_port_ipv4(4567)
            .await
            .expect("Failed to get port");

        // Construct URLs using the dynamically retrieved host and host_port
        let certs_url = format!("http://{host}:{host_port}/jwks.json");
        let token_url = format!("http://{host}:{host_port}/token");

        // Create DAPS config
        let config = config::DapsConfigBuilder::default()
            .certs_url(certs_url)
            .token_url(token_url)
            .private_key(std::path::Path::new("./testdata/connector-certificate.p12"))
            .private_key_password(Some(std::borrow::Cow::from("Password1")))
            .scope(std::borrow::Cow::from("idsc:IDS_CONNECTORS_ALL"))
            .certs_cache_ttl(1_u64)
            .build()
            .expect("Failed to build DAPS-Config");

        // Create DAPS client
        let client: ReqwestDapsClient = DapsClient::new(&config);

        // Now the test really starts...
        // Request a DAT token
        let dat = client.request_dat().await.unwrap();
        tracing::info!("DAT Token: {:?}", dat);

        // Validate the DAT token
        let cache1_start = std::time::Instant::now();
        if let Err(err) = client.validate_dat(&dat).await {
            tracing::error!("Validation failed: {:?}", err);
            panic!("Validation failed");
        } else {
            assert!(client.validate_dat(&dat).await.is_ok());
        }
        tracing::debug!("First validation took {:?}", cache1_start.elapsed());

        // Checking again to use cache
        let cache2_start = std::time::Instant::now();
        assert!(client.validate_dat(&dat).await.is_ok());
        tracing::debug!("Second validation took {:?}", cache2_start.elapsed());

        // Wait for cache to expire
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        // Now the cache should be outdated
        let cache3_start = std::time::Instant::now();
        assert!(client.validate_dat(&dat).await.is_ok());
        tracing::debug!("Third validation took {:?}", cache3_start.elapsed());
    }
}
