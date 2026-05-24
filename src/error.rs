use thiserror::Error;

/// Unified error type for all payment gateway operations.
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("Gateway '{gateway}' is not configured or not active")]
    GatewayNotConfigured { gateway: String },

    #[error("Checkout creation failed: {0}")]
    CheckoutFailed(String),

    #[error("Webhook verification failed: {0}")]
    WebhookVerificationFailed(String),

    #[error("Webhook processing failed: {0}")]
    WebhookProcessingFailed(String),

    #[error("Subscription operation failed: {0}")]
    SubscriptionFailed(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal gateway error: {0}")]
    Internal(String),
}

impl GatewayError {
    /// Returns true if this is a transient error that can be retried.
    pub fn is_retryable(&self) -> bool {
        match self {
            GatewayError::Internal(_) => true,
            _ => false,
        }
    }

    /// Returns the HTTP status code that should be returned for this error.
    pub fn http_status_code(&self) -> u16 {
        match self {
            GatewayError::GatewayNotConfigured { .. } => 400,
            GatewayError::CheckoutFailed(_) => 500,
            GatewayError::WebhookVerificationFailed(_) => 400,
            GatewayError::WebhookProcessingFailed(_) => 500,
            GatewayError::SubscriptionFailed(_) => 500,
            GatewayError::ConfigError(_) => 500,
            GatewayError::Internal(_) => 500,
        }
    }
}
