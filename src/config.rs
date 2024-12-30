use serde::Deserialize;

#[doc = "The configuration for the policy.
\n\r Must match schema.json properties."]
#[derive(Default, Clone, Deserialize)]
pub struct PolicyConfig {

    #[serde(alias = "do-validate-issuer")]
    pub do_validate_issuer: Option<bool>,

    #[serde(alias = "do-validate-audience")]
    pub do_validate_audience: Option<bool>,

    #[serde(alias = "do-validate-expiration")]
    pub do_validate_expiration: Option<bool>,

    #[serde(alias = "do-validate-algorithm")]
    pub do_validate_algorithm: Option<bool>,

    #[serde(alias = "valid-issuers")]
    pub valid_issuers: Option<Vec<String>>,

    #[serde(alias = "valid-audiences")]
    pub valid_audiences: Option<Vec<String>>,

    #[serde(alias = "valid-algorithms")]
    pub valid_algorithms: Option<Vec<String>>,

    #[serde(alias = "log-level")]
    pub log_level: Option<String>,
}