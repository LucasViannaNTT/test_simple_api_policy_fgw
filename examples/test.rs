use test_simple_api_policy_fgw::{core::auth::jwt::JWT, POLICY_ID};

fn main() {
    let input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibHVjYXMiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.FNeOQ5NtrAaNInuwp2yKf46ijPFfgwcgYmfMnFzYx7E".to_string();
    
    match JWT::from_token(&input) {
        Ok(jwt) => {
            println!("{:?}", jwt);
        },
        Err(http_error) => {
            println!("{:?}", http_error.error_message);
        }
    };
}