use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::{Method, Request, Response, StatusCode, body::Incoming};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use super::{ApiState, Body, auth, dto, error, full, no_content, probes, streams};
use crate::config::{ClashApiConfig, GroupStrategy};
use crate::control::catalog::CatalogNode;

pub async fn serve(
    mut request: Request<Incoming>,
    config: Arc<ClashApiConfig>,
    state: Arc<ApiState>,
    connection: CancellationToken,
    connection_permit: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> Result<Response<Body>, Infallible> {
    let (mut response, origin) = match auth::origin(&request, &config) {
        Err(status) => (error(status, "Origin is not allowed"), None),
        Ok(origin) => {
            let response = if request.method() == Method::OPTIONS {
                preflight(&request, &config)
            } else {
                dispatch(&mut request, &config, &state, connection, connection_permit).await
            };
            (response, origin)
        }
    };
    auth::cors(response.headers_mut(), origin.as_deref());
    if response.status().is_client_error()
        || response.status().is_server_error()
        || request.method() == Method::OPTIONS
    {
        response
            .headers_mut()
            .insert("connection", "close".parse().unwrap());
    }
    Ok(response)
}

fn preflight<B>(request: &Request<B>, config: &ClashApiConfig) -> Response<Body> {
    if let Err(status) = auth::preflight(request, config) {
        return error(status, "CORS preflight rejected");
    }
    let mut response = no_content();
    response.headers_mut().insert(
        "access-control-allow-methods",
        "GET, POST, PUT, PATCH, DELETE".parse().unwrap(),
    );
    response.headers_mut().insert(
        "access-control-allow-headers",
        "Authorization, Content-Type".parse().unwrap(),
    );
    response
        .headers_mut()
        .insert("access-control-max-age", "300".parse().unwrap());
    if config.allow_private_network {
        response.headers_mut().insert(
            "access-control-allow-private-network",
            "true".parse().unwrap(),
        );
    }
    response
}

async fn dispatch(
    request: &mut Request<Incoming>,
    config: &ClashApiConfig,
    state: &Arc<ApiState>,
    connection: CancellationToken,
    connection_permit: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> Response<Body> {
    let segments = segments(request.uri().path());
    let supported_stream = segments.as_ref().is_ok_and(|parts| {
        parts.len() == 1
            && ["connections", "traffic", "memory", "logs"].contains(&parts[0].as_str())
    });
    let websocket = request.method() == Method::GET
        && supported_stream
        && hyper_tungstenite::is_upgrade_request(request);
    if !auth::authenticated(request, config, websocket) {
        return error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }
    let body = tokio::time::timeout(
        Duration::from_secs(10),
        http_body_util::Limited::new(request.body_mut(), 64 * 1024).collect(),
    )
    .await;
    let body = match body {
        Ok(Ok(body)) => body.to_bytes(),
        Err(_) => {
            return error(
                StatusCode::REQUEST_TIMEOUT,
                "request body deadline exceeded",
            );
        }
        Ok(Err(_)) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds 64 KiB or is incomplete",
            );
        }
    };
    let query = url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<HashMap<_, _>>();
    let parts = match segments {
        Ok(parts) => parts,
        Err(()) => return error(StatusCode::BAD_REQUEST, "invalid path encoding"),
    };
    let is_subscription = supported_stream
        && request.method() == Method::GET
        && (websocket || parts[0] != "connections");
    if !is_subscription {
        return route(request.method(), &parts, &query, &body, state).await;
    }
    let subscription = match streams::Subscription::parse(&parts[0], &query) {
        Ok(subscription) => subscription,
        Err(error_value) => return error(StatusCode::BAD_REQUEST, &error_value.to_string()),
    };
    let permit = match state.runtime.subscribers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "subscription limit reached",
            );
        }
    };
    if websocket {
        let mut websocket_config =
            hyper_tungstenite::tungstenite::protocol::WebSocketConfig::default();
        websocket_config.max_message_size = Some(64 * 1024);
        websocket_config.max_frame_size = Some(64 * 1024);
        match hyper_tungstenite::upgrade(request, Some(websocket_config)) {
            Ok((response, websocket)) => {
                state.tasks.spawn(streams::websocket(
                    state.clone(),
                    websocket,
                    subscription,
                    permit,
                    connection_permit,
                ));
                response.map(|body| body.map_err(|never| match never {}).boxed_unsync())
            }
            Err(_) => error(StatusCode::BAD_REQUEST, "invalid WebSocket upgrade"),
        }
    } else {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        state.tasks.spawn(streams::http(
            state.clone(),
            sender,
            subscription,
            connection,
            permit,
        ));
        let stream = futures::stream::unfold(receiver, |mut receiver| async {
            receiver.recv().await.map(|frame| (frame, receiver))
        });
        Response::builder()
            .header("content-type", "application/json")
            .header("cache-control", "no-cache")
            .body(http_body_util::StreamBody::new(stream).boxed_unsync())
            .unwrap()
    }
}

fn segments(path: &str) -> Result<Vec<String>, ()> {
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        return Ok(Vec::new());
    }
    path.strip_prefix('/')
        .ok_or(())?
        .split('/')
        .map(|part| {
            percent_encoding::percent_decode_str(part)
                .decode_utf8()
                .map(|value| value.into_owned())
                .map_err(|_| ())
        })
        .collect()
}

async fn route(
    method: &Method,
    parts: &[String],
    query: &HashMap<String, String>,
    body: &[u8],
    state: &ApiState,
) -> Response<Body> {
    let parts: Vec<_> = parts.iter().map(String::as_str).collect();
    let generation = match state.runtime.generation() {
        Ok(generation) => generation,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "controller is not ready"),
    };
    match (method, parts.as_slice()) {
        (&Method::GET, []) => super::json(StatusCode::OK, &json!({"hello":"shoes"})),
        (&Method::GET, ["version"]) => super::json(
            StatusCode::OK,
            &json!({"version":concat!("shoes ",env!("CARGO_PKG_VERSION")),"meta":false}),
        ),
        (&Method::GET, ["configs"]) => super::json(
            StatusCode::OK,
            &json!({"mode":"rule","mode-list":["rule"],"log-level":crate::control::logs::level_name(crate::logging::default_level())}),
        ),
        (&Method::GET, ["proxies"]) => super::json(StatusCode::OK, &dto::proxies(&generation)),
        (&Method::GET, ["group"]) => super::json(StatusCode::OK, &dto::groups(&generation)),
        (&Method::GET, [kind, name]) if *kind == "proxies" || *kind == "group" => {
            if *kind == "group"
                && !matches!(
                    generation.catalog.nodes.get(*name),
                    Some(CatalogNode::Group { .. })
                )
            {
                return error(StatusCode::NOT_FOUND, "Not found");
            }
            match dto::proxy(&generation, &generation.catalog.selection.snapshot(), name) {
                Some(value) => super::json(StatusCode::OK, &value),
                None => error(StatusCode::NOT_FOUND, "Not found"),
            }
        }
        (&Method::PUT, ["proxies", name]) => {
            match generation.catalog.nodes.get(*name) {
                None => return error(StatusCode::NOT_FOUND, "Not found"),
                Some(CatalogNode::Group {
                    strategy: GroupStrategy::Selector,
                    ..
                }) => {}
                _ => return error(StatusCode::BAD_REQUEST, "Must be a Selector"),
            }
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Selection {
                name: String,
            }
            let selection: Selection = match serde_json::from_slice(body) {
                Ok(selection) => selection,
                Err(_) => return error(StatusCode::BAD_REQUEST, "invalid selection body"),
            };
            match state
                .runtime
                .select(generation.id, (*name).into(), selection.name)
                .await
            {
                Ok(()) => no_content(),
                Err(error_value) => io_error(error_value),
            }
        }
        (&Method::DELETE, ["proxies", name]) => {
            if generation.catalog.nodes.contains_key(*name) {
                error(StatusCode::BAD_REQUEST, "Selector reset is not supported")
            } else {
                error(StatusCode::NOT_FOUND, "Not found")
            }
        }
        (&Method::GET, [kind, name, "delay"]) if *kind == "proxies" || *kind == "group" => {
            let Some(node) = generation.catalog.nodes.get(*name) else {
                return error(StatusCode::NOT_FOUND, "Not found");
            };
            let group = *kind == "group";
            let query = match probes::ProbeQuery::parse(query, group) {
                Ok(query) => query,
                Err(error_value) => return io_error(error_value),
            };
            if group {
                let CatalogNode::Group { members, .. } = node else {
                    return error(StatusCode::NOT_FOUND, "Not found");
                };
                if members.len() > 1024 {
                    return error(StatusCode::BAD_REQUEST, "group exceeds probe member limit");
                }
                match probes::probe_group(&state.runtime, &generation, members, &query).await {
                    Ok(successes) => super::json(StatusCode::OK, &successes),
                    Err(error_value) => io_error(error_value),
                }
            } else {
                match probes::probe(&state.runtime, &generation, name, &query).await {
                    Ok(delay) => super::json(StatusCode::OK, &json!({"delay":delay})),
                    Err(error_value) if error_value.kind() == std::io::ErrorKind::TimedOut => {
                        error(StatusCode::GATEWAY_TIMEOUT, "Timeout")
                    }
                    Err(_) => error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "delay test failed or unavailable",
                    ),
                }
            }
        }
        (&Method::GET, ["rules"]) => {
            super::json(StatusCode::OK, &json!({"rules":generation.rules}))
        }
        (&Method::GET, ["providers", "proxies" | "rules"]) => {
            super::json(StatusCode::OK, &json!({"providers":{}}))
        }
        (&Method::GET, ["connections"]) => match streams::connections(state).await {
            Ok(bytes) => Response::builder()
                .header("content-type", "application/json")
                .body(full(bytes))
                .unwrap(),
            Err(_) => error(
                StatusCode::INSUFFICIENT_STORAGE,
                "connection snapshot exceeds 32 MiB",
            ),
        },
        (&Method::DELETE, ["connections"]) => {
            state.runtime.flows.cancel_all();
            no_content()
        }
        (&Method::DELETE, ["connections", id]) => {
            state.runtime.flows.cancel(id);
            no_content()
        }
        _ if excluded(method, &parts) => error(
            StatusCode::NOT_IMPLEMENTED,
            "operation is not supported by Shoes",
        ),
        _ => error(StatusCode::NOT_FOUND, "Not found"),
    }
}

fn excluded(method: &Method, path: &[&str]) -> bool {
    matches!(
        (method, path),
        (&Method::PATCH | &Method::PUT, ["configs"])
            | (&Method::POST, ["configs", "geo"])
            | (&Method::PATCH, ["rules", "disable"])
            | (&Method::GET, ["dns", "query"])
            | (&Method::POST, ["cache", "dns" | "fakeip", "flush"])
            | (
                &Method::GET | &Method::PUT | &Method::DELETE,
                ["storage", _]
            )
            | (&Method::POST, ["restart" | "upgrade"])
            | (&Method::POST, ["upgrade", "ui" | "geo"])
            | (&Method::PUT, ["providers", "rules" | "proxies", _])
            | (&Method::GET, ["providers", "proxies", _, "healthcheck"])
            | (&Method::GET, ["providers", "proxies", _, _, "healthcheck"])
    )
}

fn io_error(error_value: std::io::Error) -> Response<Body> {
    let status = match error_value.kind() {
        std::io::ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
        std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        std::io::ErrorKind::WouldBlock => StatusCode::SERVICE_UNAVAILABLE,
        std::io::ErrorKind::TimedOut => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error(status, &error_value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_network_preflight_requires_explicit_permission() {
        let mut config: ClashApiConfig = serde_yaml::from_str(
            "clash_api_address: '127.0.0.1:9090'\nsecret: test\ncors_origins: ['https://dashboard.example']",
        ).unwrap();
        let request = Request::builder()
            .method(Method::OPTIONS)
            .uri("/proxies")
            .header("origin", "https://dashboard.example")
            .header("access-control-request-method", "GET")
            .header("access-control-request-private-network", "true")
            .body(())
            .unwrap();
        assert!(!config.allow_private_network);
        let response = preflight(&request, &config);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-private-network")
        );
        config.allow_private_network = true;
        let response = preflight(&request, &config);
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response.headers()["access-control-allow-private-network"],
            "true"
        );
    }
}
