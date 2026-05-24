//! # CloShell Payment Gateway
//!
//! A plug-and-play payment gateway interface for Rust applications.
//!
//! This crate provides a unified trait [`PaymentGateway`] that any payment
//! gateway can implement (Stripe, PayFast, PayPal, etc.), along with a
//! [`GatewayRouter`] for managing multiple gateways simultaneously.
//!
//! ## Quick Start
//!
//! ```ignore
//! use closhell_payment_gateway::{
//!     GatewayRouter, StripeGateway, PaymentGateway,
//!     CheckoutParams, SubscriptionInterval, Currency,
//! };
//!
//! // Register gateways
//! let mut router = GatewayRouter::new();
//! router.register(StripeGateway::from_env());
//!
//! // Create a checkout
//! let params = CheckoutParams {
//!     customer_email: "user@example.com".into(),
//!     plan_name: "Professional".into(),
//!     tier: "professional".into(),
//!     interval: SubscriptionInterval::Monthly,
//!     seats: 1,
//!     unit_amount: 2999, // $29.99 in cents
//!     currency: Currency::USD,
//!     success_url: "https://example.com/success".into(),
//!     cancel_url: "https://example.com/cancel".into(),
//!     client_reference_id: "user-uuid-here".into(),
//!     metadata: std::collections::HashMap::new(),
//!     customer_id: None,
//! };
//!
//! let gateway = router.get("stripe").unwrap();
//! let result = gateway.create_checkout(params).await?;
//! // Redirect user to result.checkout_url
//! ```
//!
//! ## Adding a New Gateway
//!
//! To add a new payment gateway, implement the [`PaymentGateway`] trait:
//!
//! ```ignore
//! use async_trait::async_trait;
//! use closhell_payment_gateway::{
//!     PaymentGateway, CheckoutParams, CheckoutResult,
//!     WebhookHeaders, WebhookEventType, SubscriptionInfo,
//!     GatewayError, GatewayInfo,
//! };
//!
//! struct MyGateway { /* ... */ }
//!
//! #[async_trait]
//! impl PaymentGateway for MyGateway {
//!     async fn create_checkout(&self, params: CheckoutParams) -> Result<CheckoutResult, GatewayError> {
//!         // Your implementation
//!     }
//!     // ... implement remaining methods
//!     fn gateway_info(&self) -> GatewayInfo {
//!         GatewayInfo {
//!             name: "mygateway",
//!             display_name: "My Gateway",
//!             supported_currencies: &["usd"],
//!             supports_subscriptions: true,
//!             supports_one_time: true,
//!         }
//!     }
//! }
//! ```

pub mod error;
pub mod router;
pub mod types;
pub mod gateway_trait;
pub mod gateways;

#[cfg(feature = "stripe")]
pub use gateways::StripeGateway;

pub use gateways::SafepayGateway;

pub use error::GatewayError;
pub use gateway_trait::PaymentGateway;
pub use router::GatewayRouter;
pub use types::*;
