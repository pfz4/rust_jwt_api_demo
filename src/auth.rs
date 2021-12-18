use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use rocket::request::{self, Request, FromRequest};
use rocket::outcome::Outcome;
use rocket::State;

use jsonwebtoken;

pub struct AuthConfiguration{
    pub issuer:Issuer,
    pub audiences:Vec<String>
}

#[derive(Deserialize, Debug)]
pub struct Issuer {
    #[serde(skip_deserializing)]
    pub name:String, //url of issuer (e.g. https://example.com/auth/realms/demo)
    pub realm:String, //e.g. demo
    pub public_key:String,
    #[serde(alias = "token-service")]
    pub token_service:String,
    #[serde(alias = "account-service")]
    pub account_service:String,
    #[serde(alias = "tokens-not-before")]
    pub tokens_not_before:u32
}

impl Issuer{
    // Load Issuer Information From Keycloak Auth Endpoint (e.g. https://example.com/auth/realms/demo)
    pub async fn from_url(url:&str)->Result<Issuer, Box<dyn std::error::Error>>{
        let response = reqwest::get(url).await?;
        let mut issuer:Issuer = response.json::<Issuer>().await?;
        issuer.name = String::from(url);
        Ok(issuer)
    }

    // Parse Keycloak PublicKey to PEM
    pub fn get_pem_public_key(&self) -> String{
        let mut output_string = String::from("-----BEGIN PUBLIC KEY-----\n");

        // Add a line break every 64 characters (see: https://wiki.openssl.org/index.php/PEM)
        for (i, c) in self.public_key.chars().enumerate(){
            output_string.push(c);
            if i % 64 == 63 {
                output_string.push_str("\n");
            }
        }

        output_string.push_str("\n-----END PUBLIC KEY-----");
        output_string
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    // OAuth2 Claims

    pub aud: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub sub: String,

    // Keycloak Claims

    pub scope:String,
    pub name:String,
    pub preferred_username:String,
    pub given_name:String,
    pub family_name:String,
    pub email_verified:bool,
    pub email:String,

}

impl Token {
    pub fn from_jwt(jwt:&str, issuer:&Issuer, audience: &Vec<String>) ->Result<Token, jsonwebtoken::errors::Error>{
        let public_key_pem = issuer.get_pem_public_key();
        let public_key = jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?;
        let token = jsonwebtoken::decode::<Token>(&jwt, &public_key, &jsonwebtoken::Validation {
            validate_exp: true,
            validate_nbf: false,
            iss: Option::Some(String::from(&issuer.name)),
            algorithms: vec![jsonwebtoken::Algorithm::RS256],
            aud: Option::Some(HashSet::from_iter(audience.iter().cloned().map(|s|String::from(s)))),

            ..jsonwebtoken::Validation::default()
        })?;
        Ok(token.claims)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Token {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, ()> {
        let authorization_header_keys: Vec<_> = request.headers().get("Authorization").collect();
        if authorization_header_keys.len() != 1 {
            // No Authorization Header present, forwarding to next request handler
            return Outcome::Forward(());
        }
        let auth_configuration = request.guard::<&State<AuthConfiguration>>().await.unwrap(); // Get Auth Config from Rocket State (see: https://rocket.rs/v0.5-rc/guide/state/#state)

        let auth_header = authorization_header_keys[0].replace("Bearer ", ""); // Extract JWT Token

        match Token::from_jwt(&auth_header, &auth_configuration.issuer, &auth_configuration.audiences) {
            Ok(token) => Outcome::Success(token), // JWT Token could be parsed and is valid
            Err(e) => {println!("{:?}", e);Outcome::Forward(())} // Could not parse JWT Token (expired, wrong audience, wrong issuer, invalid, ...), forwarding to next request handler
        }
    }
}