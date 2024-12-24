pub mod jwt
{
    use std::collections::{HashMap, HashSet};
    use chrono::Utc;
    use serde::Deserialize;

    use crate::core::http::error::HttpError;

    #[derive(Default, Clone, Deserialize)]
    #[doc = "The JWT JOSE Header represents a JSON object whose members are the header parameters of the JWT."]
    pub struct JwtJOSEHeader {
        #[doc = "The typ (type) Header Parameter defined by RFC 7519."]
        #[serde(alias = "typ")]
        pub typ: String,
        #[doc = "The alg (algorithm) Header Parameter defined by RFC 7519."]
        #[serde(alias = "alg")]
        pub algorithm: String,
    }

    #[derive(Default, Clone, Deserialize)]
    #[doc = "The JWT Claims Set represents a JSON object whose members are the claims conveyed by the JWT.
    \n\rThe Claims will later be the payload of the JWT."]
    pub struct JwtClaimsSet {
        #[doc = "Registered Claim Names: iss, sub, aud, exp, nbf, iat, jti."]
        #[serde(flatten)]
        pub claims: HashMap<String, String>,
    }

    #[doc = "The JwtRegisteredClaims enum represents the registered claim names defined by RFC 7519."]
    pub enum JwtRegisteredClaims {
        Issuer,
        Subject,
        Audience,
        ExpirationTime,
        NotBefore,
        IssuedAt,
        JWTID,
    }

    impl JwtRegisteredClaims {
        #[doc = "Returns the name of the claim."]
        pub fn id(&self) -> &str {
            match self {
                JwtRegisteredClaims::Issuer => "iss",
                JwtRegisteredClaims::Subject => "sub",
                JwtRegisteredClaims::Audience => "aud",
                JwtRegisteredClaims::ExpirationTime => "exp",
                JwtRegisteredClaims::NotBefore => "nbf",
                JwtRegisteredClaims::IssuedAt => "iat",
                JwtRegisteredClaims::JWTID => "jti",
            }
        }
    }

    #[doc = "The JWT struct represents a JSON Web Token (JWT) as defined by RFC 7519."]
    pub struct Jwt{
        pub jwt_jose_header: JwtJOSEHeader,
        pub jwt_claims_set: JwtClaimsSet,
        pub jwt_signature: String,
    }

    impl Jwt {

        #[doc = "Creates a new Jws instance from a token string, containing the header, payload and signature.
        \n\r If any of the parts are not in the expected format, an error is returned."]
        pub fn from_token(token: String) -> Result<Self, HttpError> {

            fn decode(encoded: String) -> String {
                let decoded = base64::decode(&encoded).unwrap();
                String::from_utf8(decoded).unwrap()
            }

            let parts: Vec<&str> = token.split('.').collect();
            let header = decode(parts[0].to_string());
            let payload = decode(parts[1].to_string());
            let signature = decode(parts[2].to_string());
            
            let jwt_jose_header: JwtJOSEHeader = match serde_json::from_str(&header) {
                Ok(header) => header,
                Err(_) => return Err(HttpError::new(401, "Error decoding token, header does not follow expected format.".to_string())),
            };
            
            let jwt_claims_set: JwtClaimsSet = match serde_json::from_str(&payload) {
                Ok(payload) => payload,
                Err(_) => return Err(HttpError::new(401, "Error decoding token, payload does not follow expected format.".to_string())),
            };
            
            Ok(Jwt {
                jwt_jose_header,
                jwt_claims_set,
                jwt_signature: signature, // TODO Check what to do with the signature
            })
        }

        #[doc = "Validates the claims of the JWT against the expected claims.
        \n\rIf any of the claims are not in the expected format, an error is returned."]
        pub fn validate_claims(&self, expected_claims: HashMap<&str, &str>) -> Result<(), HttpError> {
            for (key, _value) in &self.jwt_claims_set.claims {
                if !expected_claims.contains_key(key.as_str()) {
                    return Err(HttpError::new(401, "Error decoding token, claim is not handled.".to_string()));
                }
            }

            Ok(())
        }

        #[doc = "Validates the algorithm of the JWT against the expected algorithm.
        \n\rIf the algorithm is not the expected one, an error is returned."]
        pub fn validate_algorithm(&self, expected_algorithm: &str) -> Result<(), HttpError> {
            let alg = &self.jwt_jose_header.algorithm;
            
            if alg != expected_algorithm {
                return Err(HttpError::new(401, "Error decoding token, algorithm does not match expected.".to_string()));
            } 

            Ok(())
        }

        #[doc = "Validates the expiration time of the JWT.
        \n\rIf the token has expired, an error is returned."]
        pub fn validate_expiration(&self) -> Result<(), HttpError> {

            let exp = match self.jwt_claims_set.claims.get(JwtRegisteredClaims::ExpirationTime.id()) {
                Some(exp) => exp,
                None => return Err(HttpError::new(401, "Error decoding token, expiration claim not found.".to_string())),
            };

            let exp_64 = match exp.parse::<i64>() {
                Ok(exp_64) => exp_64,
                Err(_) => return Err(HttpError::new(401, "Error decoding token, expiration claim is not a integer with 64 bits.".to_string())),
            };

            let now = Utc::now().timestamp();
            if now > exp_64 {
                return Err(HttpError::new(401, "Error decoding token, token has expired.".to_string()));
            }

            Ok(())
        }

        #[doc = "Validates the issuer of the JWT.
        \n\rIf the issuer is not the expected one, an error is returned."]
        pub fn validate_issuer(&self, expected_issuers: HashSet<&str>) -> Result<(), HttpError> {
            let iss = match self.jwt_claims_set.claims.get(JwtRegisteredClaims::Issuer.id()) {
                Some(iss) => iss,
                None => return Err(HttpError::new(401, "Error decoding token, issuer not found.".to_string())),
            };

            if !expected_issuers.contains(&iss.as_str()) {
                return Err(HttpError::new(401, "Error decoding token, issuer does not match expected.".to_string()));
            }

            Ok(())
        }

        #[doc = "Validates the audience of the JWT.
        \n\rIf the audience is not the expected one, an error is returned."]
        pub fn validate_audience(&self, expected_audiences: HashSet<&str>) -> Result<(), HttpError> {
            let aud = match self.jwt_claims_set.claims.get(JwtRegisteredClaims::Audience.id()) {
                Some(aud) => aud,
                None => return Err(HttpError::new(401, "Error decoding token, audience not found.".to_string())),
            };

            if !expected_audiences.contains(&aud.as_str()) {
                return Err(HttpError::new(401, "Error decoding token, audience does not match expected.".to_string()));
            }

            Ok(())
        }

        #[doc = "Validates that a claim is within some expected values.
        \n\rIf the claim is not within the expected values, an error is returned."]
        pub fn validate_claim_in<T>(&self, claim_id: &str, expected_values: HashSet<T>) -> Result<(), HttpError> where T: Eq + std::hash::Hash + std::str::FromStr {
            let claim = match self.jwt_claims_set.claims.get(claim_id) {
                Some(scopes) => scopes,
                None => return Err(HttpError::new(401, "Error decoding token, claim not found.".to_string())),
            };

            if let Some(claim) = claim.parse::<T>().ok() {
                if !expected_values.contains(&claim) {
                    return Err(HttpError::new(401, "Error decoding token, claim value does not match expected.".to_string()));
                }
                return Ok(())
            }

            Err(HttpError::new(401, "Error decoding token, could not parse value of claim".to_string()))
        }
    }
}