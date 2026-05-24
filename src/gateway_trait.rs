use async_trait::async_trait;

use crate::error::GatewayError;
use crate::types::*;

/// The core trait that every payment gateway must implement.
///
/// This trait defines a unified interface for payment gateways. Each gateway
/// (Stripe, PayFast, PayPal, etc.) implements this trait, allowing the
/// application to switch between gateways without changing business logic.
///
/// # Example
///
/// ```ignore
/// use closhell_payment_gateway::{PaymentGateway, StripeGateway, CheckoutParams};
///
/// let gateway = StripeGateway::new("sk_...".into(), "whsec_...".into());
///
/// let result = gateway.create_checkout(CheckoutParams { ... }).await?;
/// println!("Redirect user to: {}", result.checkout_url);
/// ```
#[async_trait]
pub trait PaymentGateway: Send + Sync {
    /// Create a checkout session and return a URL for the customer to complete payment.
    ///
    /// This is typically used for subscription purchases or one-time payments.
    /// The returned URL should be used to redirect the customer to the gateway's
    /// hosted payment page.
    async fn create_checkout(
        &self,
        params: CheckoutParams,
    ) -> Result<CheckoutResult, GatewayError>;

    /// Verify the signature of an incoming webhook and parse it into a
    /// unified [`WebhookEventType`].
    ///
    /// The raw payload bytes and headers from the HTTP request are passed in.
    /// The gateway is responsible for verifying authenticity (e.g., Stripe's
    /// signature verification, PayFast's ITN validation) and parsing the event.
    async fn parse_webhook(
        &self,
        payload: &[u8],
        headers: &WebhookHeaders,
    ) -> Result<WebhookEventType, GatewayError>;

    /// Retrieve details of a subscription from the gateway.
    async fn get_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<SubscriptionInfo, GatewayError>;

    /// Cancel an active subscription on the gateway.
    ///
    /// If `at_period_end` is true, the subscription continues until the end
    /// of the current billing period. If false, it's cancelled immediately.
    async fn cancel_subscription(
        &self,
        subscription_id: &str,
        at_period_end: bool,
    ) -> Result<(), GatewayError>;

    /// Return metadata about this gateway implementation.
    fn gateway_info(&self) -> GatewayInfo;
}
