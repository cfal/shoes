use crate::config::ClashApiConfig;
use hyper::{HeaderMap, Request, StatusCode};

pub fn origin<B>(
    request: &Request<B>,
    config: &ClashApiConfig,
) -> Result<Option<String>, StatusCode> {
    let mut origins = request.headers().get_all("origin").iter();
    let Some(origin) = origins.next() else {
        return Ok(None);
    };
    if origins.next().is_some() {
        return Err(StatusCode::FORBIDDEN);
    }
    let origin = origin.to_str().map_err(|_| StatusCode::FORBIDDEN)?;
    if config
        .cors_origins
        .iter()
        .any(|allowed| allowed == "*" || allowed == origin)
    {
        Ok(Some(origin.to_owned()))
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

pub fn authenticated<B>(request: &Request<B>, config: &ClashApiConfig, websocket: bool) -> bool {
    let query_token = if websocket {
        url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
            .find(|(key, value)| key == "token" && !value.is_empty())
            .map(|(_, value)| value.into_owned())
    } else {
        None
    };
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
    if !matches!(method, "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return Err(StatusCode::FORBIDDEN);
    }
    if let Some(value) = request.headers().get("access-control-request-headers") {
        let value = value.to_str().map_err(|_| StatusCode::FORBIDDEN)?;
        if value.split(',').any(|name| {
            !["authorization", "content-type"].contains(&name.trim().to_ascii_lowercase().as_str())
        }) {
            return Err(StatusCode::FORBIDDEN);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn config() -> ClashApiConfig {
        ClashApiConfig {
            bind: crate::config::BindLocation::Unspecified {},
            secret: "secret".into(),
            cors_origins: vec!["https://dashboard.example".into()],
            allow_private_network: false,
            connection_notes: false,
        }
    }

    #[test]
    fn origin_requires_exactly_one_allowed_value() {
        let config = config();
        let mut request = Request::new(());
        assert_eq!(origin(&request, &config), Ok(None));
        request
            .headers_mut()
            .append("origin", config.cors_origins[0].parse().unwrap());
        assert_eq!(
            origin(&request, &config),
            Ok(Some(config.cors_origins[0].clone()))
        );
        request
            .headers_mut()
            .append("origin", config.cors_origins[0].parse().unwrap());
        assert_eq!(origin(&request, &config), Err(StatusCode::FORBIDDEN));
        request
            .headers_mut()
            .insert("origin", "https://other.example".parse().unwrap());
        assert_eq!(origin(&request, &config), Err(StatusCode::FORBIDDEN));
        request
            .headers_mut()
            .insert("origin", HeaderValue::from_bytes(b"\xff").unwrap());
        assert_eq!(origin(&request, &config), Err(StatusCode::FORBIDDEN));
    }

    #[test]
    fn wildcard_allows_any_origin_but_still_requires_one_valid_header() {
        let mut config = config();
        config.cors_origins = vec!["*".into()];
        let mut request = Request::new(());
        assert_eq!(origin(&request, &config), Ok(None));
        for value in ["https://other.example", "http://localhost:3000", "null"] {
            request
                .headers_mut()
                .insert("origin", value.parse().unwrap());
            assert_eq!(origin(&request, &config), Ok(Some(value.into())));
        }
        request
            .headers_mut()
            .append("origin", "https://other.example".parse().unwrap());
        assert_eq!(origin(&request, &config), Err(StatusCode::FORBIDDEN));
        request
            .headers_mut()
            .insert("origin", HeaderValue::from_bytes(b"\xff").unwrap());
        assert_eq!(origin(&request, &config), Err(StatusCode::FORBIDDEN));

        config.cors_origins.clear();
        request
            .headers_mut()
            .insert("origin", "https://other.example".parse().unwrap());
        assert_eq!(origin(&request, &config), Err(StatusCode::FORBIDDEN));
        request.headers_mut().remove("origin");
        assert_eq!(origin(&request, &config), Ok(None));
    }

    #[test]
    fn websocket_uses_first_nonempty_query_token_before_header() {
        for (query, expected) in [
            ("", true),
            ("token=", true),
            ("token=&token=secret&token=wrong", true),
            ("token=wrong&token=secret", false),
        ] {
            let request = Request::builder()
                .uri(format!("/connections?{query}"))
                .header("authorization", "Bearer secret")
                .body(())
                .unwrap();
            assert_eq!(
                authenticated(&request, &config(), true),
                expected,
                "{query}"
            );
            assert!(authenticated(&request, &config(), false));
        }
    }

    #[test]
    fn preflight_header_allowlist_is_case_insensitive_but_not_empty() {
        for (headers, expected) in [
            (" Authorization, CONTENT-TYPE ", Ok(())),
            ("authorization,", Err(StatusCode::FORBIDDEN)),
            ("x-custom", Err(StatusCode::FORBIDDEN)),
        ] {
            let request = Request::builder()
                .header("access-control-request-method", "GET")
                .header("access-control-request-headers", headers)
                .body(())
                .unwrap();
            assert_eq!(preflight(&request, &config()), expected);
        }
        let request = Request::builder()
            .header("access-control-request-method", "GET")
            .header(
                "access-control-request-headers",
                HeaderValue::from_bytes(b"\xff").unwrap(),
            )
            .body(())
            .unwrap();
        assert_eq!(preflight(&request, &config()), Err(StatusCode::FORBIDDEN));
    }
}
