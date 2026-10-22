use crate::config::ClashApiConfig;
use hyper::{HeaderMap, Method, Request, StatusCode};

pub fn origin<B>(
    request: &Request<B>,
    config: &ClashApiConfig,
) -> Result<Option<String>, StatusCode> {
    let origins: Vec<_> = request.headers().get_all("origin").iter().collect();
    if origins.is_empty() {
        return Ok(None);
    }
    if origins.len() != 1 {
        return Err(StatusCode::FORBIDDEN);
    }
    let origin = origins[0].to_str().map_err(|_| StatusCode::FORBIDDEN)?;
    if config.cors_origins.iter().any(|allowed| allowed == origin) {
        Ok(Some(origin.to_owned()))
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

pub fn authenticated<B>(request: &Request<B>, config: &ClashApiConfig, websocket: bool) -> bool {
    let query_token = websocket
        .then(|| {
            url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
                .find(|(key, value)| key == "token" && !value.is_empty())
                .map(|(_, value)| value.into_owned())
        })
        .flatten();
    let header = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    query_token.as_deref().or(header).is_some_and(|token| {
        aws_lc_rs::constant_time::verify_slices_are_equal(
            token.as_bytes(),
            config.secret.as_bytes(),
        )
        .is_ok()
    })
}

pub fn cors(headers: &mut HeaderMap, origin: Option<&str>) {
    if let Some(origin) = origin {
        headers.insert(
            "access-control-allow-origin",
            origin.parse().expect("validated Origin header"),
        );
        headers.insert("vary", hyper::header::HeaderValue::from_static("Origin"));
    }
}

pub fn preflight<B>(request: &Request<B>, config: &ClashApiConfig) -> Result<(), StatusCode> {
    let method = request
        .headers()
        .get("access-control-request-method")
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    if ![
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
    ]
    .iter()
    .any(|allowed| allowed.as_str() == method)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    if request
        .headers()
        .get("access-control-request-headers")
        .is_some_and(|value| {
            value.to_str().map_or(true, |value| {
                value.split(',').any(|name| {
                    !["authorization", "content-type"]
                        .contains(&name.trim().to_ascii_lowercase().as_str())
                })
            })
        })
    {
        return Err(StatusCode::FORBIDDEN);
    }
    if request
        .headers()
        .get("access-control-request-private-network")
        .is_some_and(|value| value == "true")
        && !config.allow_private_network
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}
