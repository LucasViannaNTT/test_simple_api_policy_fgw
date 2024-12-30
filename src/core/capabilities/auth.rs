#[doc = "The jwt module contains the functionality for decoding and validating JSON Web Tokens (JWT)."]
pub mod jwt
{
    use std::{collections::HashMap, str::FromStr};
    use chrono::Utc;
    use regex::Regex;
    use serde::Deserialize;
    use serde_json::Value;

    use crate::core::http::{error::HttpError, expansion::ExpandedHttpContext};

    #[derive(Default, Clone, Deserialize, Debug)]
    #[doc = "The JWT JOSE Header represents a JSON object whose members are the header parameters of the JWT."]
    pub struct JWTJOSEHeader {
        #[doc = "The typ (type) Header Parameter defined by RFC 7519."]
        #[serde(alias = "typ")]
        pub typ: String,
        #[doc = "The alg (algorithm) Header Parameter defined by RFC 7519."]
        #[serde(alias = "alg")]
        pub algorithm: String,
    }

    #[derive(Default, Clone, Deserialize, Debug)]
    #[doc = "The JWT Claims Set represents a JSON object whose members are the claims conveyed by the JWT.
    \n\rThe Claims will later be the payload of the JWT."]
    pub struct JWTClaimsSet {
        #[serde(flatten)]
        claims: HashMap<String, Value>,
    }

    impl JWTClaimsSet {

        #[doc = "Returns the value of a claim.
        \n\rIf the claim is not found, or cannot be parsed, an error is returned."]
        pub fn get<T>(&self, claim: &str) -> Result<T, HttpError> where T: FromStr, {
            if let Some(value) = self.claims.get(claim) {
                value.as_str()
                    .ok_or_else(|| HttpError::new(401, format!("Error decoding token, claim '{}' cannot be parsed to string.", claim)))?
                    .parse::<T>()
                    .map_err(|_| HttpError::new(401, format!("Failed to parse claim '{}' as {}", claim, std::any::type_name::<T>())))
            } else {
                Err(HttpError::new(401, format!("Error decoding token, claim '{}' not found.", claim)))
            }
        }

        #[doc = "Checks if a claim is present in the claims set."]
        pub fn has(&self, claim: &str) -> bool {
            self.claims.contains_key(claim)
        }
    }

    #[derive(Debug)]
    #[doc = "The JwtRegisteredClaims enum represents the registered claim names defined by RFC 7519."]
    pub enum JWTRegisteredClaims {
        Issuer,
        Subject,
        Audience,
        ExpirationTime,
        NotBefore,
        IssuedAt,
        JWTID,
    }

    impl JWTRegisteredClaims {
        #[doc = "Returns the name of the claim."]
        pub fn id(&self) -> &str {
            match self {
                JWTRegisteredClaims::Issuer => "iss",
                JWTRegisteredClaims::Subject => "sub",
                JWTRegisteredClaims::Audience => "aud",
                JWTRegisteredClaims::ExpirationTime => "exp",
                JWTRegisteredClaims::NotBefore => "nbf",
                JWTRegisteredClaims::IssuedAt => "iat",
                JWTRegisteredClaims::JWTID => "jti",
            }
        }
    }

    #[derive(Debug)]
    #[doc = "The JWT struct represents a JSON Web Token (JWT) as defined by RFC 7519."]
    pub struct JWT{
        pub jose_header: JWTJOSEHeader,
        pub claims_set: JWTClaimsSet,
        pub signature: String,
        pub raw: String,
    }

    impl JWT {

        #[doc = "Validates the format of a token against a regular expression.
        \n\rIf the token does not follow the expected regular expression, an error is returned."]
        pub fn validate_token_format(regex : &String, token : &String) -> Result<(), HttpError> {
            let re = Regex::new(regex).unwrap();
            
            if !re.is_match(token) {
                return Err(HttpError::new(401, "Error decoding token, signature does not follow expected regular expression.".to_string()));
            }

            Ok(())
        }

        #[doc = "Creates a new JWT instance from a token string, containing the header, payload and signature.
        \n\r If the token is not in base64, or any of the parts are not in the expected format, an error is returned.
        \n\r Reminder: The Format must have been removed (e.g., Bearer ) before calling this method."]
        pub fn from_token(token: &String) -> Result<Self, HttpError> {

            fn decode(encoded: String) -> Result<String, HttpError> {
                let decoded = match base64::decode(&encoded.trim()) {
                    Ok(decoded) => decoded,
                    Err(_) => return Err(HttpError::new(401, "Error decoding token, could not decode base64.".to_string())),
                };

                match String::from_utf8(decoded) {
                    Ok(decoded_str) => Ok(decoded_str),
                    Err(e) => {
                        let error_details = format!("Invalid UTF-8 at byte position: {:?}", e.utf8_error());
                        Err(HttpError::new(401, format!("Error decoding token, could not decode UTF-8: {}", error_details)))
                    }
                }
            }

            if token.is_empty() {
                return Err(HttpError::new(401, "Error decoding token, token is empty.".to_string()));
            }

            let parts: Vec<&str> = token.split('.').collect();

            if parts.len() != 3 {
                return Err(HttpError::new(401, "Error decoding token, token does not follow expected format.".to_string()));
            }

            let header = match decode(parts[0].to_string()) {
                Ok(header) => header,
                Err(htttp_error) => return Err(htttp_error),
            };

            let payload = match decode(parts[1].to_string()) {
                Ok(payload) => payload,
                Err(http_error) => return Err(http_error),
            };

            let jwt_jose_header: JWTJOSEHeader = match serde_json::from_str(&header) {
                Ok(header) => header,
                Err(_) => return Err(HttpError::new(401, "Error decoding token, header does not follow expected format.".to_string())),
            };
            
            let jwt_claims_set: JWTClaimsSet = match serde_json::from_str(&payload) {
                Ok(payload) => payload,
                Err(_) => return Err(HttpError::new(401, "Error decoding token, payload does not follow expected format.".to_string())),
            };

            let jwt_signature = parts[2].to_string();
            
            Ok(JWT {
                jose_header: jwt_jose_header,
                claims_set: jwt_claims_set,
                signature: jwt_signature,
                raw: token.clone(), // TODO: Maybe use a reference
            })
        }

        #[doc = "Validates the claims of the JWT against the expected claims.
        \n\rIf any of the claims are not expected, an error is returned."]
        pub fn validate_claims(&self, expected_claims: HashMap<&str, &str>) -> Result<(), HttpError> {
            for (key, _value) in &self.claims_set.claims {
                if !expected_claims.contains_key(key.as_str()) {
                    return Err(HttpError::new(401, "Error decoding token, claim is not handled.".to_string()));
                }
            }

            Ok(())
        }

        #[doc = "Validates the algorithm of the JWT against the expected algorithm.
        \n\rIf the algorithm value does not match the expected, an error is returned."]
        pub fn validate_algorithm(&self, expected_algorithms: &Vec<String>) -> Result<(), HttpError> {
            let alg = &self.jose_header.algorithm;
            
            if !expected_algorithms.contains(&alg.to_string()) {
                return Err(HttpError::new(401, "Error decoding token, algorithm does not match expected.".to_string()));
            }

            Ok(())
        }

        #[doc = "Validates the expiration of the JWT.
        \n\rIf the expiration is not found, has expired, or not in the correct format, an error is returned."]
        pub fn validate_expiration(&self) -> Result<(), HttpError> {
            let exp : i64 = match self.claims_set.get(JWTRegisteredClaims::ExpirationTime.id()) {
                Ok(exp) => exp,
                Err(http_error) => return Err(http_error),
            };

            let now = Utc::now().timestamp();
            if now > exp {
                return Err(HttpError::new(401, "Error decoding token, token has expired.".to_string()));
            }

            Ok(())
        }

        #[doc = "Validates that a claim is within some expected values.
        \n\rIf the claim is not found, or does not match oneof the expected values or cannot be parsed, an error is returned."]
        pub fn validate_claim_value<T>(&self, claim_id: &str, expected_values: &Vec<T>) -> Result<(), HttpError> where T: Eq + std::hash::Hash + std::str::FromStr {
            let claim : T = match self.claims_set.get(claim_id) {
                Ok(claim) => claim,
                Err(http_error) => return Err(http_error),
            };

            if !expected_values.contains(&claim) {
                return Err(HttpError::new(401, format!("Error decoding token, {} claim value does not match expected.", claim_id)));
            }

            Ok(())
        }
    }

    pub trait JWTHttpContext : ExpandedHttpContext {
        fn get_jwt(&self) -> Option<&JWT>;
        fn get_mut_jwt(&mut self) -> Option<&mut JWT>;
    }

    pub mod okta {
        use std::{collections::HashMap, time::Duration};

        use jwt_simple::{claims::NoCustomClaims, prelude::{RS256PublicKey, RSAPublicKeyLike}};
        use proxy_wasm::traits::Context;

        use crate::core::{capabilities::cache::{Cache, StorageContext}, http::error::HttpError};

        use super::{JWTHttpContext, JWTRegisteredClaims};

        pub struct OktaValidatorConfig {
            pub timeout: u64,
            pub upstream : HashMap<String, String>,
            pub jwk_cache_id: String,
            pub jwk_cache_ttl: u64,
        }

        pub struct OktaCacheData {
            pub e : String,
            pub n : String,
            pub key : String,
            pub exp : String,
        }

        pub trait OktaValidator : JWTHttpContext + StorageContext + Context {
            fn get_okta_validator_config(&self) -> &OktaValidatorConfig;

            #[doc = "Requests Okta for validation of the JWT."]
            fn request_okta_validation(&mut self) -> Result<(), HttpError> {
                let jwt = match self.get_jwt() {
                    Some(jwt) => jwt,
                    None => return Err(HttpError::new(500, "Jwt not found in request context.".to_string())),
                };
                
                let timeout = self.get_okta_validator_config().timeout;
                let issuer = jwt.claims_set.get::<String>(JWTRegisteredClaims::Issuer.id()).unwrap().clone(); 
                let issuer = issuer.trim_matches('"').to_string();
                let issuer_split = issuer.split('/').collect::<Vec<&str>>();
                let okta_endpoint = issuer_split[2];
                let okta_issuer_id = issuer_split[4];

                let upstream = match self.get_okta_validator_config().upstream.get(&okta_endpoint.to_string()) {
                    Some(upstream) => upstream,
                    None => return Err(HttpError::new(500, format!("Upstream for {} not found.", okta_endpoint))),
                };

                match self.dispatch_http_call(
                    upstream, 
                    vec![
                        (":method", "GET"),
                        (":path",  format!("/oauth2/{}/v1/keys", okta_issuer_id).as_str()),
                        (":authority", okta_endpoint),
                    ], 
                    None, 
                    vec![], 
                    Duration::from_secs(timeout),
                ) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(HttpError::new(500, format!("Error calling Okta endpoint: {:?}", err))),
                }
            }

            // TODO Refactor this method so it doesnt rely as much on clones to avoid borrowing problems.
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
                let issuer = jwt.claims_set.get::<String>(JWTRegisteredClaims::Issuer.id()).unwrap().clone(); 
                let raw_token = jwt.raw.clone();

                let okta_response = match OktaResponse::from_vec_u8(&body) {
                    Ok(resp) => resp,
                    Err(http_error) => return self.send_http_error(http_error.clone()),
                };

                let kid_result = jwt.claims_set.get::<String>("kid");
                let token_kid = match kid_result {
                    Ok(kid) => kid,
                    Err(http_error) => return self.send_http_error(http_error.clone()),
                };

                for jwk in okta_response.jwks {
                    if jwk.kid == *token_kid {
                        match self.store_issuer_jwk(&issuer, &jwk) {
                            Ok(()) => (),
                            Err(http_error) => return self.send_http_error(http_error),
                        }

                        match self.validate_token(&jwk.e, &jwk.n, &raw_token) {
                            Ok(()) => (),
                            Err(http_error) => (), // return self.send_http_error(http_error),
                        }
                    }
                }

                self.resume_http_request();
            }

            fn store_issuer_jwk(&mut self, issuer : &String, jwk : &OktaJWK) -> Result<(), HttpError> {
                let config = self.get_okta_validator_config();
                let cache_id = config.jwk_cache_id.clone();
                let cache_ttl = config.jwk_cache_ttl.clone();
                let key = issuer.trim_matches('"').to_string() + &"/v1/keys".trim_matches('"').to_string();
                
                let cache: &mut Box<dyn Cache<OktaCacheData>> = match self.get_mut_storage().get_mut_cache::<OktaCacheData>(&cache_id) {
                    Some(cache) => cache,
                    None => match self.get_mut_storage().create_mut_cache(&cache_id) {
                        Ok(cache) => cache,
                        Err(err) => return Err(HttpError::new(500, format!("Error creating cache: {:?}", err))),
                    },
                };

                cache.as_mut().set(&cache_id, OktaCacheData { e: jwk.e.clone(), n: jwk.n.clone(), key, exp: cache_ttl.to_string() });

                return Ok(())
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
    }
}