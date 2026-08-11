//! Hysteria2 client authentication: one HTTP/3 request per QUIC connection.

use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use log::debug;
use rand::RngExt;
use rand::distr::Alphanumeric;

use crate::quic_outbound::connection::ConnectionAuthenticator;

/// The status a Hysteria2 server returns for a successful authentication.
/// Not a standard HTTP status; the protocol chose it deliberately.
const STATUS_OK: u16 = 233;

const AUTH_URI: &str = "https://hysteria/auth";

/// Random padding of the same shape the server sends back.
fn auth_padding() -> String {
    let mut rng = rand::rng();
    let length = rng.random_range(1..80);
    rng.sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn build_auth_request(password: &str, padding: &str) -> std::io::Result<http::Request<()>> {
    http::Request::post(AUTH_URI)
        .header("Hysteria-Auth", password)
        // Zero means "I do not know my own receive rate", which per the
        // protocol tells the server to run ordinary congestion control rather
        // than sending at a declared rate. That is what we want: Hysteria's
        // Brutal congestion control is not implemented here.
        .header("Hysteria-CC-RX", "0")
        .header("Hysteria-Padding", padding)
        .body(())
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("could not build the Hysteria2 auth request: {e}"),
            )
        })
}

/// Returns whether the server permits UDP.
fn interpret_auth_response<T>(response: &http::Response<T>) -> std::io::Result<bool> {
    let status = response.status().as_u16();
    if status != STATUS_OK {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "Hysteria2 authentication rejected: server answered {status}, expected {STATUS_OK}. \
                 Check the password; a server using username and password authentication expects \
                 them joined as \"<username>:<password>\"."
            ),
        ));
    }

    // The protocol names only "false" as a refusal, and an absent header means
    // the server did not say, which the reference client treats as available.
    let udp = response
        .headers()
        .get("hysteria-udp")
        .and_then(|value| value.to_str().ok())
        .map(|value| !value.eq_ignore_ascii_case("false"))
        .unwrap_or(true);

    Ok(udp)
}

/// Authenticates a Hysteria2 connection and remembers what the server said
/// about UDP.
#[derive(Debug)]
pub struct Hysteria2Authenticator {
    password: String,
    /// Whether the most recent authentication was told UDP is available.
    server_udp_enabled: AtomicBool,
}

impl Hysteria2Authenticator {
    pub fn new(password: String) -> Self {
        Self {
            password,
            server_udp_enabled: AtomicBool::new(true),
        }
    }

    /// What the server said about UDP at the last authentication.
    pub fn server_udp_enabled(&self) -> bool {
        self.server_udp_enabled.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl ConnectionAuthenticator for Hysteria2Authenticator {
    async fn authenticate(&self, connection: &quinn::Connection) -> std::io::Result<()> {
        let h3_connection = h3_quinn::Connection::new(connection.clone());
        let (mut driver, mut send_request) = h3::client::new(h3_connection)
            .await
            .map_err(|e| std::io::Error::other(format!("HTTP/3 setup failed: {e}")))?;

        // The HTTP/3 layer has to outlive this function, and two separate
        // things would otherwise tear it down. The driver must keep being
        // polled or the request never progresses; and h3 counts live
        // SendRequest handles, closing the connection with HTTP_NO_ERROR when
        // the last one drops. Since h3 closes the QUIC connection underneath
        // it, either would take every later proxy stream with it. One task
        // holds both until the connection ends on its own.
        let keepalive = send_request.clone();
        tokio::spawn(async move {
            let _keepalive = keepalive;
            let reason = driver.wait_idle().await;
            debug!("Hysteria2 HTTP/3 layer closed: {reason}");
        });

        let request = build_auth_request(&self.password, &auth_padding())?;

        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|e| std::io::Error::other(format!("auth request failed: {e}")))?;
        stream.finish().await.map_err(|e| {
            std::io::Error::other(format!("finishing the auth request failed: {e}"))
        })?;

        let response = stream
            .recv_response()
            .await
            .map_err(|e| std::io::Error::other(format!("reading the auth response failed: {e}")))?;

        let udp_enabled = interpret_auth_response(&response)?;
        self.server_udp_enabled
            .store(udp_enabled, Ordering::Relaxed);
        debug!("Hysteria2 authenticated; server UDP: {udp_enabled}");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_shape() {
        let request = build_auth_request("hunter2", "PADDING").unwrap();
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri(), "https://hysteria/auth");
        assert_eq!(request.headers()["hysteria-auth"], "hunter2");
        assert_eq!(request.headers()["hysteria-cc-rx"], "0");
        assert_eq!(request.headers()["hysteria-padding"], "PADDING");
    }

    #[test]
    fn test_request_rejects_a_password_with_control_characters() {
        // A header value cannot carry a newline. Failing loudly beats silently
        // truncating the password and reporting an authentication failure.
        assert!(build_auth_request("bad\r\nvalue", "PADDING").is_err());
    }

    #[test]
    fn test_accepts_status_233() {
        let response = http::Response::builder()
            .status(233)
            .header("Hysteria-UDP", "true")
            .body(())
            .unwrap();
        assert!(interpret_auth_response(&response).unwrap());
    }

    #[test]
    fn test_records_udp_refusal() {
        let response = http::Response::builder()
            .status(233)
            .header("Hysteria-UDP", "false")
            .body(())
            .unwrap();
        assert!(!interpret_auth_response(&response).unwrap());
    }

    #[test]
    fn test_missing_udp_header_means_udp_is_available() {
        let response = http::Response::builder().status(233).body(()).unwrap();
        assert!(interpret_auth_response(&response).unwrap());
    }

    #[test]
    fn test_rejects_any_other_status() {
        for status in [200u16, 401, 404, 500] {
            let response = http::Response::builder().status(status).body(()).unwrap();
            let err = interpret_auth_response(&response).unwrap_err().to_string();
            assert!(err.contains(&status.to_string()), "{err}");
        }
    }

    #[test]
    fn test_rejection_points_at_the_userpass_form() {
        let response = http::Response::builder().status(404).body(()).unwrap();
        let err = interpret_auth_response(&response).unwrap_err().to_string();
        assert!(
            err.contains("<username>:<password>"),
            "a server using userpass auth is otherwise an afternoon of guessing: {err}"
        );
    }

    #[test]
    fn test_padding_is_ascii_and_bounded() {
        for _ in 0..64 {
            let padding = auth_padding();
            assert!(!padding.is_empty());
            assert!(padding.len() < 80);
            assert!(padding.chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn test_authenticator_assumes_udp_until_told_otherwise() {
        let auth = Hysteria2Authenticator::new("password".to_string());
        assert!(auth.server_udp_enabled());
    }
}
