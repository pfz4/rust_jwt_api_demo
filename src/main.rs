use rocket::{routes, get, launch};
use dotenv::dotenv;
use std::env;
use rust_jwt_api_demo::auth::{AuthConfiguration, Issuer, Token};


#[get("/")]
fn index_authenticated(token:Token) -> String{
    format!("Hello, {} / {} ( {} | {} | {} )!", token.name, token.preferred_username,token.email , token.sub, token.scope)
}

#[get("/", rank=2)]
fn index() -> &'static str{
    "Hello, World!"
}



#[launch]
async fn rocket() -> _{
    dotenv().ok();

    let issuer = Issuer::from_url(&env::var("ISSUER").unwrap()).await.unwrap();
    let auth_config = AuthConfiguration{
        issuer,
        audiences: env::var("AUDIENCE").unwrap().split(" ").map(|e|e.to_string()).collect()
    };
    rocket::build()
        .manage(auth_config)
        .mount("/", routes![index_authenticated, index])
}
