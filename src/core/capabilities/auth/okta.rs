use std::{collections::HashMap, time::Duration};

use chrono::Utc;
use jwt_simple::{claims::NoCustomClaims, prelude::{RS256PublicKey, RSAPublicKeyLike}};
use proxy_wasm::traits::Context;
use serde::{Deserialize, Serialize};

use crate::core::{capabilities::cache::CacheCapability, error::HttpError};

use super::jwt::{JWTHttpCapability, JWTRegisteredClaims};

pub struct OktaValidatorConfig {
    pub timeout: u64,
    pub upstream : HashMap<String, String>,
    pub jwk_cache_id: String,
    pub jwk_cache_ttl: i64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OktaCacheIssuerData {
    pub keys : HashMap<String, OktaCacheIssuerKeyData>,
}

impl OktaCacheIssuerData {
    pub fn new() -> OktaCacheIssuerData {
        OktaCacheIssuerData { 
            keys: HashMap::new(),
        }
    }

    pub fn to_vec_u8(&self) -> Result<Vec<u8>, HttpError> {
        match serde_json::to_vec(self) {
            Ok(vec) => Ok(vec),
            Err(_) => Err(HttpError::new(500, "Error serializing Okta cache entry.".to_string())),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OktaCacheIssuerKeyData {
    pub n : String,
    pub e : String,
    pub exp : i64,
}

impl OktaCacheIssuerKeyData {
    pub fn new(n : String, e : String, exp : i64) -> OktaCacheIssuerKeyData {
        OktaCacheIssuerKeyData {
            n,
            e,
            exp,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OktaJWK {
    pub kid : String,
    pub n : String,
    pub e : String,
}

struct OktaResponse {
    pub jwks : Vec<OktaJWK>,
}

impl OktaResponse {
    pub fn from_vec_u8(vec : &Vec<u8>) -> Result<OktaResponse, HttpError> {
        let json : serde_json::Value = match serde_json::from_slice(&vec) {
            Ok(json) => json,
            Err(_) => return Err(HttpError::new(500, "Error parsing Okta response.".to_string())),
        };

        let keys = match json.get("keys") {
            Some(keys) => match keys.as_array() {
                Some(keys) => keys,
                None => return Err(HttpError::new(500, "Error parsing Okta keys array.".to_string())),
            }
            None => return Err(HttpError::new(500, "No keys found in Okta response.".to_string())),
        };

        let mut jwks : Vec<OktaJWK> = Vec::new();
        
        for key in keys {
            let kid = match key.get("kid") {
                Some(kid) => kid.as_str().unwrap().to_string(),
                None => return Err(HttpError::new(500, "No kid found in Okta key.".to_string())),
            };

            let n = match key.get("n") {
                Some(n) => n.as_str().unwrap().to_string(),
                None => return Err(HttpError::new(500, "No n found in Okta key.".to_string())),
            };

            let e = match key.get("e") {
                Some(e) => e.as_str().unwrap().to_string(),
                None => return Err(HttpError::new(500, "No e found in Okta key.".to_string())),
            };

            jwks.push(OktaJWK { kid, n, e });
        }

        return Ok(OktaResponse { jwks } );
    }
}

pub trait OktaValidatorCapability : JWTHttpCapability + CacheCapability<OktaCacheIssuerData> + Context {
    fn get_okta_validator_config(&self) -> &OktaValidatorConfig;

    #[doc = "Requests Okta for validation of the JWT."]
    fn request_okta_validation(&mut self) -> Result<(), HttpError> {
        let jwt = match self.get_jwt() {
            Some(jwt) => jwt,
            None => return Err(HttpError::new(500, "Jwt not found in request context.".to_string())),
        };
        
        let timeout = self.get_okta_validator_config().timeout;
        let issuer = jwt.claims.get::<String>(JWTRegisteredClaims::Issuer.id()).unwrap().clone(); 
        let issuer = issuer.trim_matches('"').to_string();
        let issuer_split = issuer.split('/').collect::<Vec<&str>>();
        let okta_endpoint = issuer_split[2];
        let okta_issuer_id = issuer_split[4];

        let upstream = match self.get_okta_validator_config().upstream.get(&okta_endpoint.to_string()) {
            Some(upstream) => upstream,
            None => return Err(HttpError::new(500, format!("Upstream for {} not found.", okta_endpoint))),
        };

        self.dispatch_http_call(
            upstream, 
            vec![
                (":method", "GET"),
                (":path",  format!("/oauth2/{}/v1/keys", okta_issuer_id).as_str()),
                (":authority", okta_endpoint),
            ], 
            None, 
            vec![], 
            Duration::from_secs(timeout),
        ).map(|_| ()).map_err(|err| HttpError::new(500, format!("Error dispatching Okta endpoint: {:?}", err)))
    }

    #[doc = "Handles okta validation response."]
    fn response_okta_validation(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
        
        let body = {
            let body = self.get_http_call_response_body(0, body_size);
            match body {
                Some(body) => body.clone(),
                None => return self.send_http_error(HttpError::new(500, "No response body found.".to_string())),
            }
        };

        let jwt = match self.get_mut_jwt() {
            Some(jwt) => jwt,
            None => return self.send_http_error(HttpError::new(500, "Jwt not found in request context.".to_string())),
        };

        // We unwrap, as the validation should have passed before this function gets called.
        let issuer = jwt.claims.get::<String>(JWTRegisteredClaims::Issuer.id()).unwrap().clone(); 
        let raw_token = jwt.raw.clone();

        let okta_response = match OktaResponse::from_vec_u8(&body) {
            Ok(resp) => resp,
            Err(http_error) => return self.send_http_error(http_error.clone()),
        };

        let kid_result = jwt.claims.get::<String>("kid");
        let token_kid = match kid_result {
            Ok(kid) => kid,
            Err(http_error) => return self.send_http_error(http_error.clone()),
        };

        let config = self.get_okta_validator_config();
        let issuer_str = issuer.as_str();
        let expiration = Utc::now().timestamp() + config.jwk_cache_ttl;

        for jwk in okta_response.jwks {
            if jwk.kid != *token_kid {
                continue;
            }

            let mut cache_entry = match self.read_from_cache(issuer_str, |data| {
                serde_json::from_slice(data).map_err(|_| HttpError::new(500, "Error parsing Okta cache data.".to_string()))
            }) {
                Some(cache_entry) => cache_entry.clone(),
                None => OktaCacheIssuerData::new(),
            };

            let key_data = OktaCacheIssuerKeyData::new(jwk.n.clone(), jwk.e.clone(), expiration);
            cache_entry.keys.insert(jwk.kid.clone(), key_data);

            let _ = self.write_to_cache(issuer_str, cache_entry);

            match self.validate_token(&jwk.e, &jwk.n, &raw_token) {
                Ok(()) => (),
                Err(_) => (), // return self.send_http_error(http_error),
            }
        }

        self.resume_http_request();
    }

    fn validate_token(&self, e : &str, n : &str, token : &String) -> Result<(), HttpError> {
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
}