use actix_rt::System;
use clap::ArgMatches;

use crate::handlers;
use crate::util::{read_pk, read_sk};

#[derive(Clone)]
pub struct AppState {
    pub pk: ibe::kiltz_vahlis_one::PublicKey,
    pub sk: ibe::kiltz_vahlis_one::SecretKey,
    pub irma_server_host: String,
}

pub fn exec(m: &ArgMatches) {
    let host = m.value_of("host").unwrap();
    let port = m.value_of("port").unwrap().parse::<u16>().unwrap();

    let public = m.value_of("public").unwrap();
    let secret = m.value_of("secret").unwrap();

    let irma_server_host = m.value_of("irma").unwrap().to_string();

    let state = AppState {
        pk: read_pk(public).unwrap(),
        sk: read_sk(secret).unwrap(),
        irma_server_host,
    };

    let system = System::new("main");

    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .wrap(
                actix_cors::Cors::new()
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_header("Content-Type")
                    .finish()
            )
            .data(actix_web::web::JsonConfig::default().limit(1024 * 4096))
            .data(state.clone())
            .service(
                actix_web::web::resource("/v1/parameters")
                    .route(actix_web::web::get().to(handlers::parameters)),
            )
            .service(
                actix_web::web::resource("/v1/request")
                    .route(actix_web::web::post().to(handlers::request)),
            )
            .service(
                actix_web::web::resource("/v1/request/{token}/{timestamp}")
                    .route(actix_web::web::get().to(handlers::request_fetch)),
            )
    })
    .bind(format!("{}:{}", host, port))
    .unwrap()
    .shutdown_timeout(1)
    .run();

    system.run().unwrap();
}
