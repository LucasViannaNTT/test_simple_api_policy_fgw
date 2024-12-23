use serde::Deserialize;

#[derive(Default, Clone, Deserialize)]
pub struct PolicyConfig {

    #[serde(alias = "secret-value")]
    pub secret_value: String,
}