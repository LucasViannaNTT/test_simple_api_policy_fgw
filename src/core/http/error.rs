use serde::Serialize;

pub struct HttpError {
    pub status: u32,
    pub error_message: String,
}

impl HttpError {
    pub fn new(status: u32, error_message: String) -> Self {
        Self {
            status,
            error_message,
        }
    }
}

#[derive(Serialize)]
pub struct HttpErrorBody {

    #[serde(alias = "type")]
    pub _type : String,

    #[serde(alias = "title")]
    pub title: String,

    #[serde(alias = "status")]
    pub status: u32,

    #[serde(alias = "timestamp")]
    pub timestamp: String,

    #[serde(alias = "error", skip_serializing_if = "HttpErrorBody::is_empty_or_null")]
    pub error_message: String,
}

impl HttpErrorBody {

    fn is_empty_or_null(s: &str) -> bool {
        s.is_empty() || s == "null"
    }

    pub fn with_message(status: u32, timestamp: String, error_message: String) -> Self {
        let _type = HttpErrorBody::get_error_type(status);
        let title = HttpErrorBody::get_error_title(status);
        HttpErrorBody::defined(_type, title, status, timestamp, error_message)
    }

    pub fn without_message(status: u32, timestamp: String) -> Self {
        let _type = HttpErrorBody::get_error_type(status);
        let title = HttpErrorBody::get_error_title(status);
        HttpErrorBody::defined(_type, title, status, timestamp, "".to_string())
    }

    pub fn defined(_type: String, title: String, status: u32, timestamp: String, error_message: String) -> Self {
        Self {
            _type,
            title,
            status,
            timestamp,
            error_message,
        }
    }

    pub fn build(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    pub fn get_error_type(status: u32) -> String {
        match status {
            400 => "HTTP:BAD_REQUEST".to_string(),
            401 => "HTTP:UNAUTHORIZED".to_string(),
            403 => "HTTP:FORBIDDEN".to_string(),
            404 => "HTTP:NOT_FOUND".to_string(),
            405 => "HTTP:METHOD_NOT_ALLOWED".to_string(),
            415 => "HTTP:UNSUPPORTED_MEDIA_TYPE".to_string(),
            429 => "HTTP:TOO_MANY_REQUESTS".to_string(),
            500 => "HTTP:INTERNAL_SERVER_ERROR".to_string(),
            501 => "HTTP:NOT_IMPLEMENTED".to_string(),
            502 => "HTTP:BAD_GATEWAY".to_string(),
            504 => "HTTP:GATEWAY_TIMEOUT".to_string(),
            _ => "HTTP:UNKNOWN".to_string(),
        }
    }

    pub fn get_error_title(status: u32) -> String {
        match status {
            400 => "Bad Request".to_string(),
            401 => "Unauthorized".to_string(),
            403 => "Forbidden".to_string(),
            404 => "Not Found".to_string(),
            405 => "Method Not Allowed".to_string(),
            415 => "Unsupported Media Type".to_string(),
            429 => "Too Many Requests".to_string(),
            500 => "Internal Server Error".to_string(),
            501 => "Not Implemented".to_string(),
            502 => "Bad Gateway".to_string(),
            504 => "Gateway Timeout".to_string(),
            _ => "Unknown".to_string(),
        }
    }
}