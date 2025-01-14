use std::{collections::HashMap, str::FromStr};
use chrono::Utc;
use regex::Regex;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;

use crate::core::{error::HttpError, expansion::ExpandedHttpContext};

/// The JWT JOSE Header represents a JSON object whose members are the header parameters of the JWT.
#[derive(Default, Clone, Deserialize, Debug)]
pub struct JWTHeader {
    #[serde(flatten)]
    headers: HashMap<String, Value>,
}

impl JWTHeader {
    /// Returns the value of a header.
    /// 
    /// # Returns 
    /// 
    /// - `Ok(T)` if the header is found and could be parsed to `T`.
    /// - `Err(HttpError)` if:
    ///     - The header is not found.
    ///     - The header cannot be parsed to `T`.
    pub fn get<T>(&self, header: &str) -> Result<T, HttpError> where T: FromStr, {
        if let Some(value) = self.headers.get(header) {
            value.as_str()
                .ok_or_else(|| HttpError::new(401, format!("Error decoding token, header '{}' cannot be parsed to string.", header)))?
                .parse::<T>()
                .map_err(|_| HttpError::new(401, format!("Failed to parse header '{}' as {}", header, std::any::type_name::<T>())))
        } else {
            Err(HttpError::new(401, format!("Error decoding token, header '{}' not found.", header)))
        }
    }
}

/// The JWT Claims Set represents a JSON object whose members are the claims conveyed by the JWT.
#[derive(Default, Clone, Deserialize, Debug)]
pub struct JWTClaims {
    #[serde(flatten)]
    claims: HashMap<String, Value>,
}

impl JWTClaims {

    /// Returns the value of a `claim` parsed to `T`.
    /// 
    /// # Returns
    /// - `Ok(T)` if the claim is found and could be parsed to `T`.
    /// - `Err(HttpError)` if:
    ///     - The claim is not found.
    ///     - The claim cannot be parsed to `T`.
    pub fn get<T>(&self, claim: &str) -> Result<T, HttpError> where T: DeserializeOwned, {
        match serde_json::from_value::<T>(self.claims[claim].clone()) {
            Ok(value) => Ok(value),
            Err(_) => Err(HttpError::new(401, format!("Error decoding token, claim '{}' cannot be parsed to {}.", claim, std::any::type_name::<T>()))),
        }
    }
}

/// The JWT struct represents a JSON Web Token (JWT) as defined by RFC 7519.
#[derive(Debug)]
pub struct JWT{
    pub header: JWTHeader,
    pub claims: JWTClaims,
    pub signature: String,
    pub raw: String,
}

impl JWT {

    /// Validates the JWT token format.
    /// Expects the token to match the following regex: <code>r"^[0-9a-zA-Z]*\.[0-9a-zA-Z]*\.[0-9a-zA-Z-_]*$"</code>
    /// 
    /// **Returns Err:** If the token's format is invalid.
    /// 
    /// # Examples
    /// ```
    /// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.L8i6g3PfcHlioHCCPURC9pmXT7gdJpx3kOoyAfNUwCc".to_string();
    /// 
    /// assert_eq!(JWT::validate_token_format(&token), Ok(()));
    /// 
    /// let token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.L8i6g3PfcHlioHCCPURC9pmXT7gdJpx3kOoyAfNUwCc".to_string();
    /// 
    /// assert_ne!(JWT::validate_token_format(&token), Ok(()));
    /// 
    /// let token = "eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.L8i6g3PfcHlioHCCPURC9pmXT7gdJpx3kOoyAfNUwCc".to_string();
    /// 
    /// assert_ne!(JWT::validate_token_format(&token), Ok(()));
    /// ```
    pub fn validate_token_format(token : &String) -> Result<(), HttpError> {
        let re = Regex::new(&r"^[0-9a-zA-Z]*\.[0-9a-zA-Z]*\.[0-9a-zA-Z-_]*$".to_string()).unwrap();
        
        if !re.is_match(token) {
            return Err(HttpError::new(401, "Error decoding token, signature does not follow expected regular expression.".to_string()));
        }
        Ok(())
    }

    /// Validates the JWT token format, expecting a "Bearer " before the token data.
    /// Expects the token to match the following regex: <code>r"^Bearer [0-9a-zA-Z]*\.[0-9a-zA-Z]*\.[0-9a-zA-Z-_]*$"</code>
    /// 
    /// **Returns Err:** If the token's format is invalid.
    /// 
    /// # Examples
    /// ```
    /// let token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.L8i6g3PfcHlioHCCPURC9pmXT7gdJpx3kOoyAfNUwCc".to_string();
    /// 
    /// assert_eq!(JWT::validate_token_format_with_bearer(&token), Ok(()));
    /// 
    /// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.L8i6g3PfcHlioHCCPURC9pmXT7gdJpx3kOoyAfNUwCc".to_string();
    /// 
    /// assert_ne!(JWT::validate_token_format_with_bearer(&token), Ok(()));
    /// 
    /// let token = "Bearer eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.L8i6g3PfcHlioHCCPURC9pmXT7gdJpx3kOoyAfNUwCc".to_string();
    /// 
    /// assert_ne!(JWT::validate_token_format_with_bearer(&token), Ok(()));
    /// ```
    pub fn validate_token_format_with_bearer(token : &String) -> Result<(), HttpError> {
        let re = Regex::new(&r"^Bearer [0-9a-zA-Z]*\.[0-9a-zA-Z]*\.[0-9a-zA-Z-_]*$".to_string()).unwrap();
        
        if !re.is_match(token) {
            return Err(HttpError::new(401, "Error decoding token, signature does not follow expected regular expression.".to_string()));
        }
        Ok(())
    }

    /// Creates a new <code>JWT</code> instance from a <code>token</code>, containing the header, payload and signature.
    /// 
    /// **Returns Err:** If the <code>token</code> is not in base64, or any of the parts are not in the expected format.
    /// 
    /// **Note:** The prefix must have been removed (e.g., Bearer ) before calling this method.
    /// 
    /// # Examples
    /// ```
    /// // This token is valid
    /// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.L8i6g3PfcHlioHCCPURC9pmXT7gdJpx3kOoyAfNUwCc".to_string();
    /// let jwt = JWT::from_token(&token);
    /// 
    /// assert!(jwt.is_ok());
    /// 
    /// // This token is invalid
    /// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3".to_string();
    /// let jwt = JWT::from_token(&token);
    /// 
    /// assert!(jwt.is_err());
    /// ```
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

        let jwt_jose_header: JWTHeader = match serde_json::from_str(&header) {
            Ok(header) => header,
            Err(_) => return Err(HttpError::new(401, "Error decoding token, header does not follow expected format.".to_string())),
        };
        
        let jwt_claims_set: JWTClaims = match serde_json::from_str(&payload) {
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

    /// Expect the <code>JWT</code> to have a certain <code>claim</code>.
    /// 
    /// **Returns Err:** If the <code>claim</code> is not present.
    /// 
    /// # Examples
    /// ```
    /// // This token is valid and carries only 'iss' claim
    /// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMiJ9.Rrel01QzcLt_r4txEdRbRiwrgg6awu97jWjRKmia6LI".to_string();
    /// let jwt = JWT::from_token(&token).unwrap();
    /// 
    /// assert!(jwt.expect_claim("iss").is_ok());
    /// 
    /// assert!(jwt.expect_claim("sub").is_err());
    /// ```
    pub fn expect_claim(&self, claim: &str) -> Result<(), HttpError> {
        if !self.claims.claims.contains_key(claim) {
            return Err(HttpError::new(401, "Error decoding token, claim is not expected.".to_string()));
        }

        Ok(())
    }

    /// Expect the <code>JWT</code> to have a certain <code>header</code>.
    /// 
    /// **Returns Err:** If the <code>header</code> is not present.
    /// 
    /// # Examples
    /// ```
    /// // This token is valid and carries 'alg' and 'typ' headers
    /// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMiJ9.Rrel01QzcLt_r4txEdRbRiwrgg6awu97jWjRKmia6LI".to_string();
    /// let jwt = JWT::from_token(&token).unwrap();
    /// 
    /// assert!(jwt.expect_header("alg").is_ok());
    /// 
    /// assert!(jwt.expect_header("kid").is_err());
    /// ```
    pub fn expect_header(&self, expected_header: &str) -> Result<(), HttpError> {
        if !self.header.headers.contains_key(expected_header) {
            return Err(HttpError::new(401, "Error decoding token, header is not expected.".to_string()));
        }

        Ok(())
    }

    /// Validates the <code>exp</code> of the <code>JWT</code>.
    /// 
    /// **Returns Err:** If the <code>exp</code> is not found, has expired, or not in the correct format.
    /// 
    /// # Examples
    /// ```
    /// // This token is valid and carries 'exp' header with a value of 10
    /// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMiJ9.Rrel01QzcLt_r4txEdRbRiwrgg6awu97jWjRKmia6LI".to_string();
    /// let jwt = JWT::from_token(&token).unwrap();
    /// 
    /// // Suppose Utc::now().timestamp() will return 10 or lesser
    /// assert!(jwt.validate_expiration("exp").is_ok());
    /// 
    /// // Suppose Utc::now().timestamp() will return 11 or greater
    /// assert!(jwt.validate_expiration("exp").is_err());
    /// ```
    pub fn validate_expiration(&self) -> Result<(), HttpError> {
        let exp : i64 = match self.claims.get("exp") {
            Ok(exp) => exp,
            Err(http_error) => return Err(http_error),
        };

        let now = Utc::now().timestamp();
        if now > exp {
            return Err(HttpError::new(401, "Error decoding token, token has expired.".to_string()));
        }

        Ok(())
    }

    /// Validates that a header is within some <code>expected values</code>.
    /// 
    /// **Returns Err:** If the header is not found, or does not match one of the expected values or cannot be parsed."
    /// 
    /// # Examples
    /// ```
    /// // This token is valid and carries a 'alg' header with a value of "HS256" and a header 'typ' with a value of "JWT".
    /// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMiJ9.Rrel01QzcLt_r4txEdRbRiwrgg6awu97jWjRKmia6LI".to_string();
    /// let jwt = JWT::from_token(&token).unwrap();
    /// let expected_alg_values = vec!["HS256".to_string()];
    /// 
    /// assert!(jwt.validate_header_value("alg", expected_alg_values).is_ok());
    /// 
    /// let expected_typ_values = vec!["JWK".to_string()];
    /// 
    /// assert!(jwt.validate_header_value("typ", expected_typ_values).is_err());
    /// ```
    pub fn validate_header_value<T>(&self, header_id: &str, expected_values: &Vec<T>) -> Result<(), HttpError> where T: Eq + std::hash::Hash + std::str::FromStr {
        let header : T = match self.header.get(header_id) {
            Ok(claim) => claim,
            Err(http_error) => return Err(http_error),
        };

        if !expected_values.contains(&header) {
            return Err(HttpError::new(401, format!("Error decoding token, {} claim value does not match expected.", header_id)));
        }

        Ok(())
    }

    /// Checks if a <code>expected value</code> matches the <code>JWT</code>'S <code>claim</code> value.
    /// 
    /// **Returns Err:** If the claim is not found, or does not match one of the expected values or cannot be parsed."
    /// 
    /// # Examples
    /// ```
    /// // This token is valid and carries a 'iss' claim with a value of "12" and a 'exp' claim with a value of 10.
    /// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMiJ9.Rrel01QzcLt_r4txEdRbRiwrgg6awu97jWjRKmia6LI".to_string();
    /// let jwt = JWT::from_token(&token).unwrap();
    /// let expected_iss_values = vec!["12".to_string()];
    /// 
    /// assert!(jwt.validate_claim_value("iss", expected_iss_values).is_ok());
    /// 
    /// let expected_exp_values = vec![100];
    /// 
    /// assert!(jwt.validate_claim_value("exp", expected_exp_values).is_err());
    /// ```
    pub fn validate_claim_value<T>(&self, claim: &str, expected_claim_values: &Vec<T>) -> Result<(), HttpError> where T: Eq + std::hash::Hash + DeserializeOwned {
        let claim_value : T = match self.claims.get(claim) {
            Ok(claim) => claim,
            Err(http_error) => return Err(http_error),
        };

        if !expected_claim_values.contains(&claim_value) {
            return Err(HttpError::new(401, format!("Error decoding token, {} claim value does not match expected.", claim)));
        }

        Ok(())
    }

    /// Checks if all <code>expected claim values</code> are within the <code>JWT</code>'s <code>claim</code> values.
    /// 
    /// **Returns Err:** If the claim is not found, doesn't contain all expected values, or cannot be parsed."
    /// 
    /// # Examples
    /// ```
    /// 
    /// ```
    pub fn validate_multiple_claim_values<T>(&self, claim : &str, expected_claim_values : &Vec<T>) -> Result<(), HttpError> where T: Eq + std::hash::Hash + DeserializeOwned + std::fmt::Debug { 
        let claim_values : Vec<T> = match self.claims.get(claim) {
            Ok(claims) => claims,
            Err(http_error) => return Err(http_error),
        };

        for expected_claim_values in expected_claim_values {
            if !claim_values.contains(&expected_claim_values) {
                return Err(HttpError::new(401, format!("Error decoding token, {:?} claim contains a value not expected.", claim)));
            }
        }

        Ok(())
    }
}

/// Enables access to JWT data in HttpContext.
pub trait JWTHttpCapability : ExpandedHttpContext {
    fn get_jwt(&self) -> &JWT;
    fn get_mut_jwt(&mut self) -> &mut JWT;
}
