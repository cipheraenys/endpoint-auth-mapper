mod api;
use crate::api;
use web::{routing::get, Router};

#[allow(dead_code)]
pub fn application(state: State) -> Router {
    Router::new().route("/", get(api::handler)).with_state(state)
}
