use serde::Deserialize;

pub static POLICY_DO_VALIDATE_ISSUER: &str = "do-validate-issuer";
pub static POLICY_DO_VALIDATE_AUDIENCE: &str = "do-validate-audience";
pub static POLICY_DO_VALIDATE_EXPIRATION: &str = "do-validate-expiration";
pub static POLICY_DO_VALIDATE_ALGORITHM: &str = "do-validate-algorithm";
pub static POLICY_VALID_ISSUERS: &str = "valid-issuers";
pub static POLICY_VALID_AUDIENCES: &str = "valid-audiences";
pub static POLICY_VALID_ALGORITHMS: &str = "valid-algorithms";
pub static POLICY_LOG_LEVEL: &str = "Log Level";
pub static POLICY_LOG_LEVEL_NONE: &str = "NONE";
pub static POLICY_LOG_LEVEL_INFO: &str = "INFO";
pub static POLICY_LOG_LEVEL_DEBUG: &str = "DEBUG";
pub static POLICY_LOG_LEVEL_ERROR: &str = "ERROR";

#[derive(Default, Clone, Deserialize)]
pub struct PolicyConfig {

    #[serde(alias = "do-validate-issuer")]
    pub do_validate_issuer: bool,

    #[serde(alias = "do-validate-audience")]
    pub do_validate_audience: bool,

    #[serde(alias = "do-validate-expiration")]
    pub do_validate_expiration: bool,

    #[serde(alias = "do-validate-algorithm")]
    pub do_validate_algorithm: bool,

    #[serde(alias = "valid-issuers")]
    pub valid_issuers: Vec<String>,

    #[serde(alias = "valid-audiences")]
    pub valid_audiences: Vec<String>,

    #[serde(alias = "valid-algorithms")]
    pub valid_algorithms: Vec<String>,

    #[serde(alias = "Log Level")]
    pub log_level: String,
}