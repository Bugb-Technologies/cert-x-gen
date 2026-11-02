//! Network layer for HTTP/HTTPS requests and protocol handlers

use crate::config::Config;
use crate::error::{Error, Result};
use crate::session::SessionManager;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use reqwest::{Client, ClientBuilder, Response};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Per-scan transport accounting, shared by concurrent template futures.
#[derive(Debug, Default)]
pub(crate) struct RequestStatistics {
    measured: AtomicUsize,
    unknown: AtomicBool,
}

impl RequestStatistics {
    pub(crate) fn measured(&self) -> usize {
        self.measured.load(Ordering::Relaxed)
    }

    pub(crate) fn total(&self) -> Option<usize> {
        (!self.unknown.load(Ordering::Relaxed)).then(|| self.measured())
    }
}

tokio::task_local! {
    static REQUEST_STATISTICS: Arc<RequestStatistics>;
}

/// Scope counters to this scan rather than to a reusable client or process.
pub(crate) async fn with_request_statistics<F: std::future::Future>(
    statistics: Arc<RequestStatistics>,
    future: F,
) -> F::Output {
    REQUEST_STATISTICS.scope(statistics, future).await
}

pub(crate) fn record_request() {
    let _ = REQUEST_STATISTICS.try_with(|stats| stats.measured.fetch_add(1, Ordering::Relaxed));
}

pub(crate) fn mark_requests_unknown() {
    let _ = REQUEST_STATISTICS.try_with(|stats| stats.unknown.store(true, Ordering::Relaxed));
}

/// Type alias for the rate limiter used in NetworkClient
type ClientRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Network client for making HTTP/HTTPS requests
#[derive(Debug)]
pub struct NetworkClient {
    client: Client,
    #[allow(dead_code)]
    config: Arc<Config>,
    session_manager: Arc<SessionManager>,
    rate_limiter: Option<Arc<ClientRateLimiter>>,
}

impl NetworkClient {
    /// Create a new network client
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        Self::with_session(config, Arc::new(SessionManager::new())).await
    }

    /// Create a new network client with existing session manager
    pub async fn with_session(
        config: Arc<Config>,
        session_manager: Arc<SessionManager>,
    ) -> Result<Self> {
        let mut builder = ClientBuilder::new()
            .timeout(Duration::from_secs(config.network.timeout_secs))
            .user_agent(&config.network.user_agent)
            .pool_max_idle_per_host(config.network.connection_pool_size)
            .pool_idle_timeout(Duration::from_secs(30));

        // NOTE: We intentionally do NOT use .http2_prior_knowledge() here.
        // That setting forces HTTP/2 without negotiation, which breaks compatibility
        // with HTTP/1.1-only servers (like Ollama, many REST APIs, etc.).
        // Instead, we let reqwest auto-negotiate:
        // - For HTTPS: Uses ALPN to negotiate HTTP/2 or HTTP/1.1
        // - For HTTP: Uses HTTP/1.1 (h2c requires explicit prior knowledge)

        // Configure redirects
        if config.network.follow_redirects {
            let max = config.network.max_redirects;
            builder = builder.redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() > max {
                    attempt.error("too many redirects")
                } else {
                    record_request();
                    attempt.follow()
                }
            }));
        } else {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }

        // Configure proxy if specified
        if let Some(ref proxy_url) = config.network.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| Error::config(format!("Invalid proxy URL: {}", e)))?;
            builder = builder.proxy(proxy);
        }

        let client = builder
            .build()
            .map_err(|e| Error::Network(format!("Failed to create HTTP client: {}", e)))?;

        // Initialize rate limiter if configured
        let rate_limiter = if let Some(rate_limit) = config.network.rate_limit {
            if rate_limit > 0 {
                // Create a quota that allows `rate_limit` requests per second
                let quota = Quota::per_second(
                    NonZeroU32::new(rate_limit).unwrap_or(NonZeroU32::new(1).unwrap()),
                );
                Some(Arc::new(RateLimiter::direct(quota)))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            client,
            config,
            session_manager,
            rate_limiter,
        })
    }

    /// Get session manager
    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }

    /// Make a GET request
    pub async fn get(&self, url: &str) -> Result<Response> {
        self.get_with_headers(url, HashMap::new()).await
    }

    /// Make a GET request with headers
    pub async fn get_with_headers(
        &self,
        url: &str,
        headers: HashMap<String, String>,
    ) -> Result<Response> {
        let max_retries = self.config.execution.max_retries;
        let mut attempt = 0;
        let domain = crate::utils::extract_domain(url);

        loop {
            tracing::debug!("GET {} (attempt {})", url, attempt + 1);

            // Apply stealth mode random delays
            if self.config.execution.stealth_mode {
                let base_delay = Duration::from_millis(500); // Base delay of 500ms
                let jitter = fastrand::u64(0..=base_delay.as_millis() as u64 / 2); // Random 0-50% of base
                let delay = base_delay + Duration::from_millis(jitter);
                tracing::debug!(
                    "Stealth mode: Adding random delay of {:?} before request",
                    delay
                );
                tokio::time::sleep(delay).await;
            }

            // Apply rate limiting if configured
            if let Some(ref limiter) = self.rate_limiter {
                limiter.until_ready().await;
            }

            let mut request = self.client.get(url);

            // Add custom headers
            for (key, value) in &headers {
                request = request.header(key, value);
            }

            // Add cookies from session
            if let Some(cookie_header) = self.session_manager.get_cookie_header(&domain).await {
                request = request.header("Cookie", cookie_header);
            }

            // Add JWT if available
            if let Some(jwt_header) = self.session_manager.get_jwt_header("default").await {
                request = request.header("Authorization", jwt_header);
            }

            record_request();
            match request.send().await {
                Ok(response) => {
                    // Check if response is retryable (5xx status codes)
                    let status = response.status();
                    if status.is_server_error() && attempt < max_retries {
                        tracing::warn!("Server error {} for {}, retrying...", status.as_u16(), url);
                        attempt += 1;
                        let base_delay =
                            Duration::from_secs(self.config.execution.retry_delay_secs);
                        let delay = base_delay * 2_u32.pow(attempt - 1);
                        tracing::debug!(
                            "Retrying {} after {:?} (attempt {})",
                            url,
                            delay,
                            attempt + 1
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    // Process Set-Cookie headers
                    self.process_response_cookies(&domain, &response).await;
                    return Ok(response);
                }
                Err(e) => {
                    // Check if error is retryable
                    let is_retryable = e.is_timeout()
                        || e.is_connect()
                        || e.is_request()
                        || matches!(e.status(), Some(status) if status.is_server_error());

                    if is_retryable && attempt < max_retries {
                        tracing::warn!("Request failed for {}: {}, retrying...", url, e);
                        attempt += 1;
                        let base_delay =
                            Duration::from_secs(self.config.execution.retry_delay_secs);
                        let delay = base_delay * 2_u32.pow(attempt - 1);
                        tracing::debug!(
                            "Retrying {} after {:?} (attempt {})",
                            url,
                            delay,
                            attempt + 1
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    return Err(Error::Network(format!("GET request failed: {}", e)));
                }
            }
        }
    }

    /// Make a POST request
    pub async fn post(&self, url: &str, body: String) -> Result<Response> {
        self.post_with_headers(url, body, HashMap::new()).await
    }

    /// Make a POST request with headers
    pub async fn post_with_headers(
        &self,
        url: &str,
        body: String,
        headers: HashMap<String, String>,
    ) -> Result<Response> {
        let max_retries = self.config.execution.max_retries;
        let mut attempt = 0;
        let domain = crate::utils::extract_domain(url);

        loop {
            tracing::debug!("POST {} (attempt {})", url, attempt + 1);

            // Apply stealth mode random delays
            if self.config.execution.stealth_mode {
                let base_delay = Duration::from_millis(500); // Base delay of 500ms
                let jitter = fastrand::u64(0..=base_delay.as_millis() as u64 / 2); // Random 0-50% of base
                let delay = base_delay + Duration::from_millis(jitter);
                tracing::debug!(
                    "Stealth mode: Adding random delay of {:?} before request",
                    delay
                );
                tokio::time::sleep(delay).await;
            }

            // Apply rate limiting if configured
            if let Some(ref limiter) = self.rate_limiter {
                limiter.until_ready().await;
            }

            let mut request = self.client.post(url).body(body.clone());

            // Add custom headers
            for (key, value) in &headers {
                request = request.header(key, value);
            }

            // Add cookies from session
            if let Some(cookie_header) = self.session_manager.get_cookie_header(&domain).await {
                request = request.header("Cookie", cookie_header);
            }

            // Add JWT if available
            if let Some(jwt_header) = self.session_manager.get_jwt_header("default").await {
                request = request.header("Authorization", jwt_header);
            }

            record_request();
            match request.send().await {
                Ok(response) => {
                    // Check if response is retryable (5xx status codes)
                    let status = response.status();
                    if status.is_server_error() && attempt < max_retries {
                        tracing::warn!("Server error {} for {}, retrying...", status.as_u16(), url);
                        attempt += 1;
                        let base_delay =
                            Duration::from_secs(self.config.execution.retry_delay_secs);
                        let delay = base_delay * 2_u32.pow(attempt - 1);
                        tracing::debug!(
                            "Retrying {} after {:?} (attempt {})",
                            url,
                            delay,
                            attempt + 1
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    // Process Set-Cookie headers
                    self.process_response_cookies(&domain, &response).await;
                    return Ok(response);
                }
                Err(e) => {
                    // Check if error is retryable
                    let is_retryable = e.is_timeout()
                        || e.is_connect()
                        || e.is_request()
                        || matches!(e.status(), Some(status) if status.is_server_error());

                    if is_retryable && attempt < max_retries {
                        tracing::warn!("Request failed for {}: {}, retrying...", url, e);
                        attempt += 1;
                        let base_delay =
                            Duration::from_secs(self.config.execution.retry_delay_secs);
                        let delay = base_delay * 2_u32.pow(attempt - 1);
                        tracing::debug!(
                            "Retrying {} after {:?} (attempt {})",
                            url,
                            delay,
                            attempt + 1
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    return Err(Error::Network(format!("POST request failed: {}", e)));
                }
            }
        }
    }

    /// Process cookies from response
    async fn process_response_cookies(&self, domain: &str, response: &Response) {
        for cookie in response.headers().get_all("set-cookie") {
            if let Ok(cookie_str) = cookie.to_str() {
                if let Err(e) = self
                    .session_manager
                    .parse_set_cookie(domain, cookie_str)
                    .await
                {
                    tracing::warn!("Failed to parse cookie: {}", e);
                }
            }
        }
    }

    /// Make a custom request
    pub async fn request(&self, builder: reqwest::RequestBuilder) -> Result<Response> {
        record_request();
        builder
            .send()
            .await
            .map_err(|e| Error::Network(format!("Request failed: {}", e)))
    }

    /// Get the underlying client
    pub fn client(&self) -> &Client {
        &self.client
    }
}

/// Protocol handler trait
#[async_trait::async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// Get protocol name
    fn name(&self) -> &str;

    /// Get default port
    fn default_port(&self) -> u16;

    /// Probe if target supports this protocol
    async fn probe(&self, target: &crate::types::Target) -> bool;

    /// Execute protocol-specific request
    async fn execute(&self, request: ProtocolRequest) -> Result<ProtocolResponse>;
}

/// Generic protocol request
#[derive(Debug, Clone)]
pub struct ProtocolRequest {
    /// Target address
    pub address: String,
    /// Target port
    pub port: u16,
    /// Request data
    pub data: Vec<u8>,
    /// Timeout
    pub timeout: Duration,
}

/// Generic protocol response
#[derive(Debug, Clone)]
pub struct ProtocolResponse {
    /// Response data
    pub data: Vec<u8>,
    /// Response time
    pub response_time: Duration,
    /// Success indicator
    pub success: bool,
}

/// HTTP protocol handler
#[derive(Debug)]
pub struct HttpHandler {
    client: Arc<NetworkClient>,
}

impl HttpHandler {
    /// Create a new HTTP handler
    pub fn new(client: Arc<NetworkClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl ProtocolHandler for HttpHandler {
    fn name(&self) -> &str {
        "http"
    }

    fn default_port(&self) -> u16 {
        80
    }

    async fn probe(&self, target: &crate::types::Target) -> bool {
        let url = target.url();
        self.client.get(&url).await.is_ok()
    }

    async fn execute(&self, request: ProtocolRequest) -> Result<ProtocolResponse> {
        let url = format!("http://{}:{}", request.address, request.port);
        let start = std::time::Instant::now();

        match self.client.get(&url).await {
            Ok(response) => {
                let data = response
                    .bytes()
                    .await
                    .map_err(|e| Error::Network(format!("Failed to read response: {}", e)))?
                    .to_vec();

                Ok(ProtocolResponse {
                    data,
                    response_time: start.elapsed(),
                    success: true,
                })
            }
            Err(_e) => Ok(ProtocolResponse {
                data: Vec::new(),
                response_time: start.elapsed(),
                success: false,
            }),
        }
    }
}

/// DNS resolver
#[derive(Debug)]
pub struct DnsResolver {
    resolver: trust_dns_resolver::TokioAsyncResolver,
}

impl DnsResolver {
    /// Create a new DNS resolver
    pub async fn new() -> Result<Self> {
        let resolver = trust_dns_resolver::TokioAsyncResolver::tokio(
            trust_dns_resolver::config::ResolverConfig::default(),
            trust_dns_resolver::config::ResolverOpts::default(),
        );

        Ok(Self { resolver })
    }

    /// Resolve hostname to IP addresses
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>> {
        let response =
            self.resolver
                .lookup_ip(hostname)
                .await
                .map_err(|e| Error::DnsResolution {
                    hostname: hostname.to_string(),
                    error: e.to_string(),
                })?;

        Ok(response.iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_scans_on_one_client_keep_separate_request_totals() {
        let mut server = mockito::Server::new_async().await;
        let a = server
            .mock("GET", "/a")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;
        let b = server
            .mock("GET", "/b")
            .with_status(200)
            .expect(2)
            .create_async()
            .await;
        let client = NetworkClient::new(Arc::new(Config::default()))
            .await
            .unwrap();
        let first = Arc::new(RequestStatistics::default());
        let second = Arc::new(RequestStatistics::default());
        tokio::join!(
            with_request_statistics(first.clone(), async {
                client.get(&format!("{}/a", server.url())).await.unwrap();
            }),
            with_request_statistics(second.clone(), async {
                mark_requests_unknown();
                for _ in 0..2 {
                    client.get(&format!("{}/b", server.url())).await.unwrap();
                }
            }),
        );
        a.assert_async().await;
        b.assert_async().await;
        assert_eq!(first.total(), Some(1));
        assert_eq!(second.total(), None);
        assert_eq!(second.measured(), 2);
    }

    #[tokio::test]
    async fn test_network_client_creation() {
        let config = Arc::new(Config::default());
        let client = NetworkClient::new(config).await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_dns_resolver() {
        let resolver = DnsResolver::new().await;
        assert!(resolver.is_ok());
    }
}
