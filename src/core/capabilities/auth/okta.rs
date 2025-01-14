use std::{collections::HashMap, time::Duration};

use chrono::Utc;
use jwt_simple::{claims::NoCustomClaims, prelude::{RS256PublicKey, RSAPublicKeyLike}};
use proxy_wasm::traits::Context;
use serde::{Deserialize, Serialize};

use crate::core::{capabilities::cache::CacheCapability, error::HttpError};

use super::jwt::JWTHttpCapability;

/// Configuration for the Okta validator service.
pub struct OktaValidatorConfig {
    /// Timeout duration in seconds for Okta requests
    pub timeout: u64,
    /// Mapping of Okta endpoints to their upstream servers
    pub upstream : HashMap<String, String>,
    /// Time-to-live in seconds for cached JWK Issuer keys
    pub issuer_key_data_ttl: i64,
}

impl OktaValidatorConfig {
    /// Creates a new `OktaValidatorConfig` with the specified parameters.
    /// # Arguments
    /// * `timeout` - Request timeout in seconds
    /// * `upstream` - HashMap mapping Okta endpoints to upstream servers. To define a fallback endpoint, map the `"default"` key with the desired endpoint.
    /// * `jwk_cache_id` - Identifier for the JWK cache
    /// * `issuer_key_data_ttl` - Issuer Key Data TTL in seconds
    pub fn new(timeout: u64, upstream: HashMap<String, String>, issuer_key_data_ttl: i64) -> OktaValidatorConfig {
        OktaValidatorConfig {
            timeout,
            upstream,
            issuer_key_data_ttl,
        }
    }
}

/// Represents cached data for an Okta issuer, including its JWK keys.
#[derive(Clone, Serialize, Deserialize)]
pub struct OktaCacheIssuerData {
    pub keys : HashMap<String, OktaCacheIssuerKeyData>,
}

impl OktaCacheIssuerData {
    /// Creates a new empty OktaCacheIssuerData instance.
    pub fn new() -> OktaCacheIssuerData {
        OktaCacheIssuerData { 
            keys: HashMap::new(),
        }
    }

    /// Serializes the cache data to a byte vector.
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)` if serialization succeeds
    /// - `Err(HttpError)` if serialization fails
    pub fn to_vec_u8(&self) -> Result<Vec<u8>, HttpError> {
        match serde_json::to_vec(self) {
            Ok(vec) => Ok(vec),
            Err(_) => Err(HttpError::new(500, "Error serializing Okta cache entry.".to_string())),
        }
    }
}

/// Represents cached key data for a specific Okta issuer key.
#[derive(Clone, Serialize, Deserialize)]
pub struct OktaCacheIssuerKeyData {
    pub n : String,
    pub e : String,
    pub exp : i64,
}

impl OktaCacheIssuerKeyData {
    /// Creates a new OktaCacheIssuerKeyData instance.
    pub fn new(n : String, e : String, exp : i64) -> OktaCacheIssuerKeyData {
        OktaCacheIssuerKeyData {
            n,
            e,
            exp,
        }
    }
}

/// Represents a JSON Web Key returned by Okta's JWKS endpoint.
#[derive(Clone, Serialize, Deserialize)]
pub struct OktaJWK {
    #[serde(alias = "kty")]
    pub kty: String,
    #[serde(alias = "alg")]
    pub alg : String,
    #[serde(alias = "kid")]
    pub kid : String,
    #[serde(alias = "use")]
    pub _use : String,
    #[serde(alias = "e")]
    pub e : String,
    #[serde(alias = "n")]
    pub n : String,
}

impl OktaJWK {
    /// Creates a new OktaJWK instance.
    pub fn new(kty: String, alg: String, kid: String, _use: String, e: String, n: String) -> OktaJWK {
        OktaJWK { kty, alg, kid, _use, e, n, }
    }
}

/// Represents a response from Okta's JWKS endpoint containing multiple JWKs.
#[derive(Clone, Serialize, Deserialize)]
struct OktaResponse {
    #[serde(alias = "keys")]
    pub keys : Vec<OktaJWK>,
}

impl OktaResponse {
    /// Creates an OktaResponse from a byte vector.
    ///
    /// # Arguments
    /// * `vec` - Byte vector containing the serialized response
    ///
    /// # Returns
    /// - `Ok(OktaResponse)` if parsing succeeds
    /// - `Err(HttpError)` if parsing fails
    pub fn from_vec_u8(vec : &Vec<u8>) -> Result<OktaResponse, HttpError> {
        match serde_json::from_slice(vec) {
            Ok(response) => Ok(response),
            Err(_) => return Err(HttpError::new(500, "Error parsing Okta response.".to_string())),
        }
    }
}

pub trait OktaValidatorCapability : JWTHttpCapability + CacheCapability<OktaCacheIssuerData> + Context {
    fn get_okta_validator_config(&self) -> &OktaValidatorConfig;

    /// Validates a JWT token by making a request to Okta's validation endpoint.
    ///
    /// # Returns
    /// - `Ok(())` if the HTTP call was successfully dispatched
    /// - `Err(HttpError)` if:
    ///   - The issuer claim cannot be extracted from the JWT
    ///   - The issuer string doesn't contain the expected Okta endpoint or ServerID
    ///   - No matching or default upstream configuration is found
    ///   - The HTTP dispatch fails
    /// 
    /// # Steps
    /// 1. Extract the issuer claim from the JWT
    /// 2. Parse the Okta endpoint and ServerID from the issuer string
    /// 3. Determine the appropriate upstream configuration for the Okta endpoint
    /// 4. Make a HTTP call to Okta's key validation endpoint
    /// 
    /// # Examples
    /// ```
    /// // After validating the JWT, we could call
    /// match self.request_okta_validation() {
    ///    // This will pause until we validate Okta's response
    ///    Ok(()) => return Action::Pause,
    ///    // This will resume and send the HTTP error
    ///    Err(http_error) => {
    ///        self.send_http_error(http_error);
    ///        return Action::Continue;
    ///    }
    ///}
    /// ```
    fn request_okta_validation(&mut self) -> Result<(), HttpError> {

        let jwt = self.get_jwt();
        
        let issuer = match jwt.claims.get::<String>("iss") {
            Ok(jwt_issuer) => jwt_issuer,
            Err(http_error) => return Err(http_error),
        };

        let issuer: String = issuer.trim_matches('"').to_string();
        let issuer_split = issuer.split('/').collect::<Vec<&str>>();

        let okta_endpoint = match issuer_split.get(2) {
            Some(endpoint) => *endpoint,
            None => return Err(HttpError::new(500, "No Okta endpoint found in issuer.".to_string())),
        };

        let okta_server_id = match issuer_split.get(4) {
            Some(server_id) => *server_id,
            None => return Err(HttpError::new(500, "No Okta issuer ID found in issuer.".to_string())),
        };

        let upstream = match self.get_okta_validator_config().upstream.get(&okta_endpoint.to_string()) {
            Some(upstream) => upstream,
            None => match self.get_okta_validator_config().upstream.get("default") {
                Some(upstream) => upstream,
                None => return Err(HttpError::new(500, "No default upstream found.".to_string())),
            }
        };

        let timeout = self.get_okta_validator_config().timeout;
        let duration = Duration::from_secs(timeout);

        if let Err(error) = self.dispatch_http_call(
            upstream, 
            vec![
                (":method", "GET"),
                (":path",  format!("/oauth2/{}/v1/keys", okta_server_id).as_str()),
                (":authority", okta_endpoint),
            ], 
            None, 
            vec![], 
            duration,
        ) {
            let url = issuer + &"/v1/keys".to_string();
            return Err(HttpError::new(500, format!("Error dispatching Okta request. URL: {:?}, ERROR:{:?}",  url, error)))
        };

        Ok(())
    }

    /// Processes and handles the response from Okta's validation endpoint.
    ///
    /// # Arguments
    /// * `body_size` - Size of the response body.
    /// 
    /// # Returns
    /// - `Ok(())` if the validation is successful
    /// - `Err(HttpError)` if:
    ///   - The response body is missing or invalid
    ///   - The Okta response cannot be parsed
    ///   - The JWT claims are invalid
    ///   - The JWT algorithm does not match JWK algorithm
    ///   - Token validation fails
    ///   - Cache operations fail
    /// 
    /// # Steps
    /// 1. Retrieves and validates the HTTP response body
    /// 2. Extracts the issuer, key ID (KID) and algorithm from the JWT
    /// 3. Parses the Okta response body containing JSON Web Keys (JWK)
    /// 4. For JWK's KIDs that match JWT's KID:
    ///    - Check if JWK's algorithm matches the JWT's algorithm
    ///    - Updates the cache with the new key data
    ///    - Validates the token using the JWK components
    /// 
    /// # Examples
    /// Suppose this code in inside `Context` implementation:
    /// ```
    /// fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
    ///     match self.response_okta_validation(body_size) {
    ///         // Token is valid, we can resume
    ///         Ok(()) => self.resume_http_request(),
    ///         // Token is invalid, we send an HTTP error
    ///         Err(http_error) => self.send_http_error(http_error),
    ///     }
    /// } 
    /// ```
    fn response_okta_validation(&mut self, body_size: usize) -> Result<(), HttpError> {

        /// Validates a JWT token using RSA-256 public key components.
        ///
        /// # Returns
        /// - `Ok(())` if the token is successfully validated
        /// - `Err(HttpError)` if:
        ///   - Base64URL decoding of the key components fails
        ///   - Public key construction fails
        ///   - Token verification fails
        /// 
        /// # Steps
        /// 1. Decodes the base64url-encoded RSA public key components (e, n)
        /// 2. Constructs an RS256 public key from the decoded components
        /// 3. Verifies the token signature using the constructed public key
        fn validate_token(e : &str, n : &str, token : &String) -> Result<(), HttpError> {
            let e = match base64_url::decode(e) {
                Ok(e) => e,
                Err(err) => return Err(HttpError::new(500, format!("Error parsing public key: {:?}", err))),
            };

            let n = match base64_url::decode(n) {
                Ok(n) => n,
                Err(err) => return Err(HttpError::new(500, format!("Error parsing public key: {:?}", err))),
            };

            let public_key = match RS256PublicKey::from_components(&n, &e) {
                Ok(public_key) => public_key,
                Err(err) => return Err(HttpError::new(500, format!("Error parsing public key: {:?}", err))),
            };

            match public_key.verify_token::<NoCustomClaims>(token, None) {
                Ok(_) => Ok(()),
                Err(err) => return Err(HttpError::new(500, format!("Error verifying token: {:?}", err))),
            }
        }
        
        let body = match {
            let body = self.get_http_call_response_body(0, body_size);
            
            match body {
                Some(body) => Ok(body.clone()),
                None => return Err(HttpError::new(500, "No response body found.".to_string())),
            }
        } {
            Ok(body) => body,
            Err(http_error) => return http_error,
        };

        let jwt = self.get_mut_jwt();

        let jwt_issuer = match jwt.claims.get::<String>("iss") {
            Ok(jwt_issuer) => jwt_issuer,
            Err(http_error) => return Err(http_error),
        };

        let jwt_alg = match jwt.header.get::<String>("alg") {
            Ok(alg) => alg,
            Err(http_error) => return Err(http_error),
        };

        let jwt_kid = match jwt.header.get::<String>("kid") {
            Ok(kid) => kid,
            Err(http_error) => return Err(http_error),
        };

        let jwt_raw = jwt.raw.clone();

        let okta_response = match OktaResponse::from_vec_u8(&body) {
            Ok(resp) => resp,
            Err(http_error) => return Err(http_error),
        };

        let okta_config = self.get_okta_validator_config();
        let jwt_issuer_str = jwt_issuer.as_str();
        let expiration = Utc::now().timestamp() + okta_config.issuer_key_data_ttl;

        for jwk in okta_response.keys {
            // Ignore KIDs that don't match the JWT's KID
            if jwk.kid != jwt_kid {
                continue;
            }

            // TODO ASK Does the algorithm has to be verified?
            if jwk.alg != jwt_alg {
                return Err(HttpError::new(500,format!("Invalid algorithm for JWK: expected {}, got {}", jwt_alg, jwk.alg)));
            }

            let mut issuer_data = match self.read_from_cache(jwt_issuer_str, |data| {
                serde_json::from_slice(data).map_err(|_| HttpError::new(500, "Error parsing Okta cache data.".to_string()))
            }) {
                // Issuer data found, clone to allow changing the data
                Some(issuer_data) => issuer_data.clone(),
                // Issuer data not found, create a new one
                None => OktaCacheIssuerData::new(),
            };

            if let Err(http_error) = validate_token(&jwk.e, &jwk.n, &jwt_raw) {
                return Err(http_error);
            }

            let issuer_key_data = OktaCacheIssuerKeyData::new(jwk.n.clone(), jwk.e.clone(), expiration);
            issuer_data.keys.insert(jwk.kid.clone(), issuer_key_data);

            // Overwrite the issuer data in the cache with the updated one
            let _ = self.write_to_cache(jwt_issuer_str, issuer_data);
        }
        return Ok(())
    }
}