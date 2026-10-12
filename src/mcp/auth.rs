//! Bearer token authorization for the MCP endpoint.
//!
//! The token is passed from 1C as a parameter of `Запустить` and is always
//! required: without a valid `Authorization: Bearer <token>` header the
//! request is rejected with `401` before reaching the MCP transport or 1C.

use std::convert::Infallible;
use std::fmt;
use std::sync::Arc;

use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use tower::{Layer, Service};

use super::server::{BoxFutureResponse, BoxResponse};

const MIN_TOKEN_LEN: usize = 32;

#[derive(Clone)]
pub(super) struct BearerToken(Arc<str>);

impl BearerToken {
    pub(super) fn new(raw: &str) -> Result<Self, String> {
        let value = raw.trim_start_matches('\u{feff}').trim();
        if value.len() < MIN_TOKEN_LEN {
            return Err(format!("токен короче {MIN_TOKEN_LEN} символов"));
        }
        if !value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("токен содержит недопустимые символы".to_owned());
        }
        Ok(Self(Arc::from(value)))
    }

    fn matches(&self, authorization: Option<&HeaderValue>) -> bool {
        let Some(value) = authorization.and_then(|value| value.to_str().ok()) else {
            return false;
        };
        let Some((scheme, presented)) = value.split_once(' ') else {
            return false;
        };
        scheme.eq_ignore_ascii_case("bearer")
            && constant_time_eq(presented.trim().as_bytes(), self.0.as_bytes())
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerToken(***)")
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let diff = left
        .iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    std::hint::black_box(diff) == 0
}

#[derive(Clone)]
pub(super) struct BearerAuthLayer {
    pub(super) token: Option<BearerToken>,
}

impl<S> Layer<S> for BearerAuthLayer {
    type Service = BearerAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BearerAuthService {
            inner,
            token: self.token.clone(),
        }
    }
}

#[derive(Clone)]
pub(super) struct BearerAuthService<S> {
    inner: S,
    token: Option<BearerToken>,
}

impl<S, B> Service<Request<B>> for BearerAuthService<S>
where
    S: Service<Request<B>, Response = BoxResponse, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = BoxResponse;
    type Error = Infallible;
    type Future = BoxFutureResponse;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        if let Some(token) = &self.token {
            if !token.matches(req.headers().get(header::AUTHORIZATION)) {
                return Box::pin(async { Ok(unauthorized_response()) });
            }
        }

        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move { inner.call(req).await })
    }
}

fn unauthorized_response() -> BoxResponse {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Bearer")
        .body(Full::new(Bytes::from("Unauthorized")).boxed())
        .expect("valid response")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn header(value: &str) -> HeaderValue {
        HeaderValue::from_str(value).unwrap()
    }

    #[test]
    fn token_requires_min_length_and_visible_ascii() {
        assert!(BearerToken::new("short").is_err());
        assert!(BearerToken::new("").is_err());
        assert!(BearerToken::new("0123456789abcdef 0123456789abcdef").is_err());
        assert!(BearerToken::new("0123456789abcdef0123456789abcdeё").is_err());
        assert!(BearerToken::new(TOKEN).is_ok());
    }

    #[test]
    fn token_is_trimmed_and_bom_is_ignored() {
        let token = BearerToken::new(&format!("\u{feff}{TOKEN}\r\n")).unwrap();
        assert!(token.matches(Some(&header(&format!("Bearer {TOKEN}")))));
    }

    #[test]
    fn matches_bearer_scheme_case_insensitively() {
        let token = BearerToken::new(TOKEN).unwrap();
        assert!(token.matches(Some(&header(&format!("bearer {TOKEN}")))));
        assert!(!token.matches(Some(&header(&format!("Basic {TOKEN}")))));
        assert!(!token.matches(Some(&header(TOKEN))));
        assert!(!token.matches(Some(&header("Bearer 0123456789abcdef0123456789abcdeX"))));
        assert!(!token.matches(None));
    }

    #[test]
    fn debug_does_not_reveal_token() {
        let token = BearerToken::new(TOKEN).unwrap();
        assert!(!format!("{token:?}").contains(TOKEN));
    }
}
