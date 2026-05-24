use std::collections::HashMap;

use async_trait::async_trait;
use stripe::Client as StripeClient;

use crate::error::GatewayError;
use crate::types::*;
use crate::gateway_trait::PaymentGateway;

/// Stripe payment gateway implementation.
///
/// Wraps the `async-stripe` crate and implements the [`PaymentGateway`] trait.
///
/// # Example
///
/// ```ignore
/// use closhell_payment_gateway::{StripeGateway, PaymentGateway};
///
/// let gateway = StripeGateway::new(
///     "sk_test_...".into(),
///     "whsec_...".into(),
/// );
/// ```
#[derive(Clone)]
pub struct StripeGateway {
    client: StripeClient,
    webhook_secret: String,
}

impl StripeGateway {
    /// Create a new Stripe gateway instance.
    ///
    /// * `secret_key` - Your Stripe secret key (starts with `sk_`)
    /// * `webhook_secret` - Your Stripe webhook signing secret (starts with `whsec_`)
    pub fn new(secret_key: String, webhook_secret: String) -> Self {
        StripeGateway {
            client: StripeClient::new(secret_key),
            webhook_secret,
        }
    }

    /// Create from environment variables:
    /// - `STRIPE_SECRET_KEY`
    /// - `STRIPE_WEBHOOK_SECRET`
    pub fn from_env() -> Self {
        let secret_key = std::env::var("STRIPE_SECRET_KEY").unwrap_or_default();
        let webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_default();
        Self::new(secret_key, webhook_secret)
    }
}

#[async_trait]
impl PaymentGateway for StripeGateway {
    async fn create_checkout(
        &self,
        params: CheckoutParams,
    ) -> Result<CheckoutResult, GatewayError> {
        let mut checkout_params = stripe::CreateCheckoutSession::new();

        // Customer
        checkout_params.customer_email = Some(&params.customer_email);

        // Mode: always Subscription for now (can be extended for one-time payments)
        checkout_params.mode = Some(stripe::CheckoutSessionMode::Subscription);

        // URLs
        checkout_params.success_url = Some(&params.success_url);
        checkout_params.cancel_url = Some(&params.cancel_url);
        checkout_params.client_reference_id = Some(&params.client_reference_id);

        // Build product data
        let product_name = format!("{} ({} Seat{})",
            params.plan_name,
            params.seats,
            if params.seats > 1 { "s" } else { "" }
        );

        let product_data = stripe::CreateCheckoutSessionLineItemsPriceDataProductData {
            name: product_name,
            ..Default::default()
        };

        let recurring = stripe::CreateCheckoutSessionLineItemsPriceDataRecurring {
            interval: match params.interval {
                SubscriptionInterval::Yearly =>
                    stripe::CreateCheckoutSessionLineItemsPriceDataRecurringInterval::Year,
                SubscriptionInterval::Monthly =>
                    stripe::CreateCheckoutSessionLineItemsPriceDataRecurringInterval::Month,
            },
            ..Default::default()
        };

        let price_data = stripe::CreateCheckoutSessionLineItemsPriceData {
            currency: map_currency(&params.currency),
            product_data: Some(product_data),
            recurring: Some(recurring),
            unit_amount: Some(params.unit_amount),
            tax_behavior: None,
            unit_amount_decimal: None,
            product: None,
        };

        let line_item = stripe::CreateCheckoutSessionLineItems {
            price_data: Some(price_data),
            quantity: Some(1),
            ..Default::default()
        };
        checkout_params.line_items = Some(vec![line_item]);

        // Metadata
        checkout_params.metadata = Some(params.metadata.clone());

        // Create session
        let session = stripe::CheckoutSession::create(&self.client, checkout_params)
            .await
            .map_err(|e| {
                tracing::error!("Stripe create checkout error: {}", e);
                GatewayError::CheckoutFailed(e.to_string())
            })?;

        let checkout_url = session.url.unwrap_or_default();
        let session_id = session.id.to_string();

        Ok(CheckoutResult {
            checkout_url,
            gateway: "stripe".to_string(),
            session_id,
        })
    }

    async fn parse_webhook(
        &self,
        payload: &[u8],
        headers: &WebhookHeaders,
    ) -> Result<WebhookEventType, GatewayError> {
        let payload_str = std::str::from_utf8(payload)
            .map_err(|e| GatewayError::WebhookProcessingFailed(e.to_string()))?;

        let event_json: serde_json::Value = serde_json::from_str(payload_str)
            .map_err(|e| GatewayError::WebhookProcessingFailed(e.to_string()))?;

        // Signature verification
        if !self.webhook_secret.is_empty() && self.webhook_secret != "whsec_placeholder" {
            match stripe::Webhook::construct_event(
                payload_str,
                &headers.signature,
                &self.webhook_secret,
            ) {
                Ok(_) => {
                    // Signature is valid, proceed
                }
                Err(stripe::WebhookError::BadParse(_)) => {
                    tracing::warn!(
                        "Stripe event parsing failed (possibly API version mismatch), \
                         but signature is valid. Falling back to manual extraction."
                    );
                }
                Err(e) => {
                    tracing::error!("Stripe signature verification failed: {:?}", e);
                    return Err(GatewayError::WebhookVerificationFailed(e.to_string()));
                }
            }
        } else {
            tracing::warn!(
                "STRIPE_WEBHOOK_SECRET is empty or placeholder. \
                 Skipping signature verification (not recommended for production)."
            );
        }

        // Parse event type
        let event_type_str = event_json
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("");

        tracing::info!("Received Stripe webhook event: {}", event_type_str);

        match event_type_str {
            "checkout.session.completed" => {
                let data = event_json
                    .get("data")
                    .and_then(|d| d.get("object"))
                    .ok_or_else(|| {
                        GatewayError::WebhookProcessingFailed(
                            "Missing data.object in checkout.session.completed".into(),
                        )
                    })?;

                let metadata: HashMap<String, String> = data
                    .get("metadata")
                    .and_then(|m| serde_json::from_value(m.clone()).ok())
                    .unwrap_or_default();

                let completed = CheckoutCompletedData {
                    session_id: data.get("id").and_then(|i| i.as_str()).unwrap_or_default().to_string(),
                    customer_id: data.get("customer").and_then(|c| c.as_str()).map(|s| s.to_string()),
                    subscription_id: data.get("subscription").and_then(|s| s.as_str()).map(|s| s.to_string()),
                    amount_total: data.get("amount_total").and_then(|a| a.as_i64()).unwrap_or(0),
                    currency: data.get("currency").and_then(|c| c.as_str()).unwrap_or("usd").to_string(),
                    tier: data.get("metadata")
                        .and_then(|m| m.get("tier"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("pro")
                        .to_string(),
                    interval: data.get("metadata")
                        .and_then(|m| m.get("interval"))
                        .and_then(|i| i.as_str())
                        .unwrap_or("monthly")
                        .to_string(),
                    client_reference_id: data.get("client_reference_id")
                        .and_then(|c| c.as_str())
                        .map(|s| s.to_string())
                        .or_else(|| metadata.get("user_id").cloned()),
                    seats: metadata.get("seats").and_then(|s| s.parse().ok()),
                    metadata,
                };

                Ok(WebhookEventType::CheckoutCompleted(completed))
            }

            "customer.subscription.deleted" => {
                let data = event_json
                    .get("data")
                    .and_then(|d| d.get("object"));

                let subscription_id = data
                    .and_then(|sub| sub.get("id"))
                    .and_then(|i| i.as_str())
                    .unwrap_or_default()
                    .to_string();

                Ok(WebhookEventType::SubscriptionDeleted(SubscriptionDeletedData {
                    subscription_id,
                }))
            }

            "customer.subscription.updated" => {
                let data = event_json.get("data").and_then(|d| d.get("object"));
                let subscription_id = data
                    .and_then(|sub| sub.get("id"))
                    .and_then(|i| i.as_str())
                    .unwrap_or_default()
                    .to_string();
                let status = data
                    .and_then(|sub| sub.get("status"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                Ok(WebhookEventType::SubscriptionUpdated {
                    subscription_id,
                    status,
                })
            }

            "invoice.paid" => {
                let data = event_json.get("data").and_then(|d| d.get("object"));
                Ok(WebhookEventType::InvoicePaid {
                    invoice_id: data.and_then(|inv| inv.get("id")).and_then(|i| i.as_str()).unwrap_or_default().to_string(),
                    subscription_id: data.and_then(|inv| inv.get("subscription")).and_then(|s| s.as_str()).map(|s| s.to_string()),
                    amount_paid: data.and_then(|inv| inv.get("amount_paid")).and_then(|a| a.as_i64()).unwrap_or(0),
                    currency: data.and_then(|inv| inv.get("currency")).and_then(|c| c.as_str()).unwrap_or("usd").to_string(),
                })
            }

            "invoice.payment_failed" => {
                let data = event_json.get("data").and_then(|d| d.get("object"));
                Ok(WebhookEventType::InvoicePaymentFailed {
                    invoice_id: data.and_then(|inv| inv.get("id")).and_then(|i| i.as_str()).unwrap_or_default().to_string(),
                    subscription_id: data.and_then(|inv| inv.get("subscription")).and_then(|s| s.as_str()).map(|s| s.to_string()),
                })
            }

            _ => {
                tracing::info!("Unhandled Stripe event type: {}", event_type_str);
                Ok(WebhookEventType::Unknown {
                    event_type: event_type_str.to_string(),
                    raw_data: event_json,
                })
            }
        }
    }

    async fn get_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<SubscriptionInfo, GatewayError> {
        let sub = stripe::Subscription::retrieve(
            &self.client,
            &subscription_id.parse().map_err(|e| {
                GatewayError::SubscriptionFailed(format!("Invalid subscription ID: {}", e))
            })?,
            &[],
        )
        .await
        .map_err(|e| {
            tracing::error!("Stripe get subscription error: {}", e);
            GatewayError::SubscriptionFailed(e.to_string())
        })?;

        Ok(SubscriptionInfo {
            subscription_id: sub.id.to_string(),
            customer_id: match &sub.customer {
                stripe::Expandable::Id(id) => id.to_string(),
                stripe::Expandable::Object(obj) => obj.id.to_string(),
            },
            status: map_stripe_status(&sub.status),
            current_period_end: chrono::DateTime::from_timestamp(
                sub.current_period_end,
                0,
            )
            .unwrap_or_else(|| chrono::Utc::now()),
            tier: sub.metadata.get("tier").cloned(),
            cancel_at_period_end: sub.cancel_at_period_end,
        })
    }

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
        at_period_end: bool,
    ) -> Result<(), GatewayError> {
        if at_period_end {
            let params = stripe::UpdateSubscription {
                cancel_at_period_end: Some(true),
                ..Default::default()
            };
            stripe::Subscription::update(
                &self.client,
                &subscription_id.parse().map_err(|e| {
                    GatewayError::SubscriptionFailed(format!("Invalid subscription ID: {}", e))
                })?,
                params,
            )
            .await
            .map_err(|e| {
                tracing::error!("Stripe update subscription error: {}", e);
                GatewayError::SubscriptionFailed(e.to_string())
            })?;
        } else {
            stripe::Subscription::cancel(
                &self.client,
                &subscription_id.parse().map_err(|e| {
                    GatewayError::SubscriptionFailed(format!("Invalid subscription ID: {}", e))
                })?,
                stripe::CancelSubscription::default(),
            )
            .await
            .map_err(|e| {
                tracing::error!("Stripe cancel subscription error: {}", e);
                GatewayError::SubscriptionFailed(e.to_string())
            })?;
        }

        Ok(())
    }

    fn gateway_info(&self) -> GatewayInfo {
        GatewayInfo {
            name: "stripe",
            display_name: "Stripe",
            supported_currencies: &["usd", "eur", "gbp", "cad", "aud", "inr"],
            supports_subscriptions: true,
            supports_one_time: true,
        }
    }
}

// ── Helpers ──────────────────────────────────────────

fn map_currency(currency: &Currency) -> stripe::Currency {
    match currency {
        Currency::USD => stripe::Currency::USD,
        Currency::EUR => stripe::Currency::EUR,
        Currency::GBP => stripe::Currency::GBP,
        Currency::CAD => stripe::Currency::CAD,
        Currency::AUD => stripe::Currency::AUD,
        Currency::INR => stripe::Currency::INR,
        _ => stripe::Currency::USD, // Fallback
    }
}

fn map_stripe_status(status: &stripe::SubscriptionStatus) -> SubscriptionStatus {
    match status {
        stripe::SubscriptionStatus::Active => SubscriptionStatus::Active,
        stripe::SubscriptionStatus::PastDue => SubscriptionStatus::PastDue,
        stripe::SubscriptionStatus::Trialing => SubscriptionStatus::Trialing,
        stripe::SubscriptionStatus::Canceled => SubscriptionStatus::Cancelled,
        stripe::SubscriptionStatus::Incomplete => SubscriptionStatus::Incomplete,
        // Handle any other variants
        _ => SubscriptionStatus::Unknown(status.to_string()),
    }
}
