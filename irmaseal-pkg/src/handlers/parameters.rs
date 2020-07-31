use crate::server::AppState;
use actix_web::web::{Data, HttpResponse};
use irmaseal_core::api::Parameters;

pub fn parameters(state: Data<AppState>) -> HttpResponse {
    let parameters = Parameters {
        format_version: 0x00,
        max_age: 300,
        public_key: state.pk.into(),
    };

    HttpResponse::Ok().json(parameters)
}
