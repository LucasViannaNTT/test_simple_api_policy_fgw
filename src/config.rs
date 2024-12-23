use serde::Deserialize;

#[derive(Default, Clone, Deserialize)]
pub struct CustomAuthConfig {

    #[serde(alias = "secret-value")]
    pub secret_value: String,
}