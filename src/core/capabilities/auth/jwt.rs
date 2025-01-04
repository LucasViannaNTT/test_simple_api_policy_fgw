use std::{collections::HashMap, str::FromStr};
use chrono::Utc;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{error::HttpError, expansion::ExpandedHttpContext};

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
    pub header: JWTJOSEHeader,
    pub claims: JWTClaimsSet,
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
            header: jwt_jose_header,
            claims: jwt_claims_set,
            signature: jwt_signature,
            raw: token.clone(), // TODO: Maybe use a reference
        })
    }

    #[doc = "Validates the claims of the JWT against the expected claims.
    \n\rIf any of the claims are not expected, an error is returned."]
    pub fn validate_claims(&self, expected_claims: HashMap<&str, &str>) -> Result<(), HttpError> {
        for (key, _value) in &self.claims.claims {
            if !expected_claims.contains_key(key.as_str()) {
                return Err(HttpError::new(401, "Error decoding token, claim is not handled.".to_string()));
            }
        }

        Ok(())
    }

    #[doc = "Validates the algorithm of the JWT against the expected algorithm.
    \n\rIf the algorithm value does not match the expected, an error is returned."]
    pub fn validate_algorithm(&self, expected_algorithms: &Vec<String>) -> Result<(), HttpError> {
        let alg = &self.header.algorithm;
        
        if !expected_algorithms.contains(&alg.to_string()) {
            return Err(HttpError::new(401, "Error decoding token, algorithm does not match expected.".to_string()));
        }

        Ok(())
    }

    #[doc = "Validates the expiration of the JWT.
    \n\rIf the expiration is not found, has expired, or not in the correct format, an error is returned."]
    pub fn validate_expiration(&self) -> Result<(), HttpError> {
        let exp : i64 = match self.claims.get(JWTRegisteredClaims::ExpirationTime.id()) {
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
        let claim : T = match self.claims.get(claim_id) {
            Ok(claim) => claim,
            Err(http_error) => return Err(http_error),
        };

        if !expected_values.contains(&claim) {
            return Err(HttpError::new(401, format!("Error decoding token, {} claim value does not match expected.", claim_id)));
        }

        Ok(())
    }
}

pub trait JWTHttpCapability : ExpandedHttpContext {
    fn get_jwt(&self) -> Option<&JWT>;
    fn get_mut_jwt(&mut self) -> Option<&mut JWT>;
}
