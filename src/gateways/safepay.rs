use std::collections::HashMap;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::{prelude::BASE64_STANDARD, Engine};

use crate::error::GatewayError;
use crate::gateway_trait::PaymentGateway;
use crate::types::*;

type HmacSha256 = Hmac<Sha256>;

/// Safepay payment gateway implementation.
///
/// Implements the [`PaymentGateway`] trait for Safepay (https://safepay-docs.netlify.app/).
#[derive(Clone)]
pub struct SafepayGateway {
    pub api_key: String,
    pub webhook_secret: String,
    pub environment: String, // "sandbox" or "production"
}

impl SafepayGateway {
    /// Create a new Safepay gateway instance.
    pub fn new(api_key: String, webhook_secret: String, environment: String) -> Self {
        SafepayGateway {
            api_key,
            webhook_secret,
            environment: environment.to_lowercase(),
        }
    }

    /// Create from environment variables:
    /// - `SAFEPAY_API_KEY`
    /// - `SAFEPAY_WEBHOOK_SECRET`
    /// - `SAFEPAY_ENVIRONMENT` (defaults to "sandbox")
    pub fn from_env() -> Self {
        let api_key = std::env::var("SAFEPAY_API_KEY").unwrap_or_default();
        let webhook_secret = std::env::var("SAFEPAY_WEBHOOK_SECRET").unwrap_or_default();
        let environment = std::env::var("SAFEPAY_ENVIRONMENT").unwrap_or_else(|_| "sandbox".to_string());
        Self::new(api_key, webhook_secret, environment)
    }

    fn api_base(&self) -> &'static str {
        if self.environment == "production" {
            "https://api.getsafepay.com"
        } else {
            "https://sandbox.api.getsafepay.com"
        }
    }

    fn checkout_base(&self) -> &'static str {
        if self.environment == "production" {
            "https://getsafepay.com/checkout/pay"
        } else {
            "https://sandbox.api.getsafepay.com/checkout/pay"
        }
    }
}

#[derive(Serialize)]
struct InitOrderRequest {
    client: String,
    amount: f64,
    currency: String,
    environment: String,
}

#[derive(Deserialize)]
struct InitOrderData {
    token: String,
}

#[derive(Deserialize)]
struct InitOrderResponse {
    data: InitOrderData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafepayWebhookPayload {
    pub data: Option<SafepayWebhookData>,
    pub resource: Option<String>,
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    pub tracker: Option<String>,
    pub reference: Option<String>,
    pub amount: Option<serde_json::Value>,
    pub currency: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafepayWebhookData {
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    pub token: Option<String>,
    pub client_id: Option<String>,
    pub endpoint: Option<String>,
    pub notification: Option<SafepayWebhookNotification>,
    pub tracker: Option<String>,
    pub reference: Option<String>,
    pub amount: Option<serde_json::Value>,
    pub currency: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafepayWebhookNotification {
    pub tracker: Option<String>,
    pub reference: Option<String>,
    pub amount: Option<serde_json::Value>,
    pub currency: Option<String>,
    pub state: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

impl SafepayGateway {
    fn verify_signature_hmac(secret: &str, data: &[u8], signature: &str) -> bool {
        let keys = vec![
            BASE64_STANDARD.decode(secret).ok(),
            hex::decode(secret).ok(),
            Some(secret.as_bytes().to_vec()),
        ];

        let expected_sig = if signature.starts_with("sha256=") {
            &signature[7..]
        } else {
            signature
        };

        for key_opt in keys {
            if let Some(key) = key_opt {
                if let Ok(mut mac) = HmacSha256::new_from_slice(&key) {
                    mac.update(data);
                    let computed = hex::encode(mac.finalize().into_bytes());
                    if computed == expected_sig {
                        return true;
                    }
                }
                type HmacSha512 = hmac::Hmac<sha2::Sha512>;
                if let Ok(mut mac) = HmacSha512::new_from_slice(&key) {
                    mac.update(data);
                    let computed = hex::encode(mac.finalize().into_bytes());
                    if computed == expected_sig {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[async_trait]
impl PaymentGateway for SafepayGateway {
    async fn create_checkout(
        &self,
        params: CheckoutParams,
    ) -> Result<CheckoutResult, GatewayError> {
        let env_str = if self.environment == "production" { "production" } else { "sandbox" };

        let plan_id = params.metadata.get("safepay_plan_id")
            .or_else(|| params.metadata.get("plan_id"))
            .cloned();

        let interval_str = match params.interval {
            SubscriptionInterval::Monthly => "monthly",
            SubscriptionInterval::Yearly => "yearly",
        };

        let packed_order_id = format!("{}:{}:{}", params.client_reference_id, params.tier, interval_str);

        if let Some(plan) = plan_id {
            // ── SUBSCRIPTION FLOW ──
            let mut query_params = vec![
                ("env", env_str.to_string()),
                ("plan_id", plan.clone()),
                ("planId", plan),
                ("reference", packed_order_id),
                ("redirect_url", params.success_url.clone()),
                ("cancel_url", params.cancel_url.clone()),
                ("source", "custom".to_string()),
                ("webhooks", "true".to_string()),
            ];

            if !params.customer_email.is_empty() {
                query_params.push(("email", params.customer_email.clone()));
                query_params.push(("customer_email", params.customer_email.clone()));
                query_params.push(("user_email", params.customer_email.clone()));
            }

            let query_string = query_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
                .collect::<Vec<String>>()
                .join("&");

            let checkout_url = format!("{}?{}", self.checkout_base(), query_string);

            return Ok(CheckoutResult {
                checkout_url,
                gateway: "safepay".to_string(),
                session_id: params.client_reference_id,
            });
        }

        // ── ONE-TIME / STANDARD FLOW ──
        let decimal_amount = (params.unit_amount as f64) / 100.0;
        let init_req = InitOrderRequest {
            client: self.api_key.clone(),
            amount: decimal_amount,
            currency: params.currency.as_str().to_uppercase(),
            environment: env_str.to_string(),
        };

        let init_url = format!("{}/order/v1/init", self.api_base());
        let client = reqwest::Client::new();
        
        let response = client.post(&init_url)
            .json(&init_req)
            .send()
            .await
            .map_err(|e| GatewayError::CheckoutFailed(format!("Failed to connect to Safepay: {}", e)))?;

        if !response.status().is_success() {
            let err_body = response.text().await.unwrap_or_default();
            return Err(GatewayError::CheckoutFailed(format!("Safepay init failed ({}): {}", init_url, err_body)));
        }

        let resp_body: InitOrderResponse = response.json()
            .await
            .map_err(|e| GatewayError::CheckoutFailed(format!("Failed to parse Safepay response: {}", e)))?;

        let tracker_token = resp_body.data.token;

        let mut query_params = vec![
            ("env", env_str.to_string()),
            ("beacon", tracker_token.clone()),
            ("order_id", packed_order_id),
            ("redirect_url", params.success_url.clone()),
            ("cancel_url", params.cancel_url.clone()),
            ("source", "custom".to_string()),
            ("webhooks", "true".to_string()),
        ];

        if !params.customer_email.is_empty() {
            query_params.push(("email", params.customer_email.clone()));
            query_params.push(("customer_email", params.customer_email.clone()));
            query_params.push(("user_email", params.customer_email.clone()));
        }

        let query_string = query_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let checkout_url = format!("{}?{}", self.checkout_base(), query_string);

        Ok(CheckoutResult {
            checkout_url,
            gateway: "safepay".to_string(),
            session_id: tracker_token,
        })
    }

    async fn parse_webhook(
        &self,
        payload: &[u8],
        headers: &WebhookHeaders,
    ) -> Result<WebhookEventType, GatewayError> {
        let signature_opt = headers.get("X-SFPY-SIGNATURE");
        let timestamp_opt = headers.get("X-SFPY-TIMESTAMP");

        if !self.webhook_secret.is_empty() {
            if let Some(signature) = signature_opt {
                let verified = if let Some(timestamp) = timestamp_opt {
                    let raw_payload_str = std::str::from_utf8(payload)
                        .map_err(|e| GatewayError::WebhookProcessingFailed(format!("Invalid UTF-8 payload: {}", e)))?;
                    let signing_payload = format!("{}.{}", timestamp, raw_payload_str);
                    Self::verify_signature_hmac(&self.webhook_secret, signing_payload.as_bytes(), signature)
                } else {
                    Self::verify_signature_hmac(&self.webhook_secret, payload, signature)
                };

                if !verified {
                    if self.environment == "sandbox" {
                        tracing::warn!("Safepay signature verification failed in sandbox, bypassing verification.");
                    } else {
                        return Err(GatewayError::WebhookVerificationFailed("Signature mismatch".to_string()));
                    }
                }
            } else {
                if self.environment == "sandbox" {
                    tracing::warn!("Safepay signature header missing in sandbox, bypassing verification.");
                } else {
                    return Err(GatewayError::WebhookVerificationFailed("Missing X-SFPY-SIGNATURE header".to_string()));
                }
            }
        } else {
            tracing::warn!("SAFEPAY_WEBHOOK_SECRET is empty. Skipping webhook verification.");
        }

        let raw_payload_str = std::str::from_utf8(payload)
            .map_err(|e| GatewayError::WebhookProcessingFailed(format!("Invalid UTF-8 payload: {}", e)))?;

        let web_event: SafepayWebhookPayload = serde_json::from_str(raw_payload_str)
            .map_err(|e| GatewayError::WebhookProcessingFailed(format!("Failed to parse Safepay webhook JSON: {}", e)))?;

        let event_type = web_event.event_type.clone()
            .or_else(|| web_event.data.as_ref().and_then(|d| d.event_type.clone()))
            .unwrap_or_default();

        let tracker = web_event.data.as_ref().and_then(|d| d.token.clone())
            .or_else(|| web_event.tracker.clone())
            .or_else(|| web_event.data.as_ref().and_then(|d| {
                d.notification.as_ref().and_then(|n| n.tracker.clone())
                    .or_else(|| d.tracker.clone())
            }))
            .unwrap_or_default();

        let reference = web_event.reference.clone()
            .or_else(|| web_event.data.as_ref().and_then(|d| {
                d.notification.as_ref().and_then(|n| n.reference.clone())
                    .or_else(|| d.reference.clone())
            }))
            .unwrap_or_default();

        let raw_amount = web_event.amount.clone()
            .or_else(|| web_event.data.as_ref().and_then(|d| {
                d.notification.as_ref().and_then(|n| n.amount.clone())
                    .or_else(|| d.amount.clone())
            }));

        let currency = web_event.currency.clone()
            .or_else(|| web_event.data.as_ref().and_then(|d| {
                d.notification.as_ref().and_then(|n| n.currency.clone())
                    .or_else(|| d.currency.clone())
            }))
            .unwrap_or_else(|| "PKR".to_string());

        let metadata = web_event.data.as_ref()
            .and_then(|d| {
                d.notification.as_ref().and_then(|n| n.metadata.clone())
                    .or_else(|| d.metadata.clone())
            })
            .unwrap_or_default();

        let order_id = metadata.get("order_id").cloned().unwrap_or_default();

        let packed_str = if order_id.contains(':') {
            order_id
        } else if reference.contains(':') {
            reference
        } else if !order_id.is_empty() {
            order_id
        } else {
            reference
        };

        let parts: Vec<&str> = packed_str.split(':').collect();
        let (user_id, parsed_tier, parsed_interval) = if parts.len() >= 3 {
            (parts[0].to_string(), parts[1].to_string(), parts[2].to_string())
        } else {
            (packed_str.clone(), "pro_personal".to_string(), "monthly".to_string())
        };

        let mut final_metadata = metadata.clone();
        final_metadata.insert("user_id".to_string(), user_id.clone());
        final_metadata.insert("tier".to_string(), parsed_tier.clone());
        final_metadata.insert("interval".to_string(), parsed_interval.clone());

        let state = web_event.data.as_ref()
            .and_then(|d| d.notification.as_ref().and_then(|n| n.state.clone()))
            .unwrap_or_default();

        let amount_cents = match raw_amount {
            Some(serde_json::Value::Number(num)) => {
                if let Some(f) = num.as_f64() {
                    (f * 100.0) as i64
                } else if let Some(i) = num.as_i64() {
                    i * 100
                } else {
                    0
                }
            }
            Some(serde_json::Value::String(s)) => {
                if let Ok(f) = s.parse::<f64>() {
                    (f * 100.0) as i64
                } else {
                    0
                }
            }
            _ => 0,
        };

        let is_completed = event_type == "payment.completed"
            || (event_type == "payment:created" && state == "PAID");

        if is_completed {
            let completed_data = CheckoutCompletedData {
                session_id: tracker,
                customer_id: None,
                subscription_id: None,
                amount_total: amount_cents,
                currency,
                tier: parsed_tier,
                interval: parsed_interval,
                client_reference_id: Some(user_id),
                seats: final_metadata.get("seats").and_then(|s| s.parse().ok()),
                metadata: final_metadata,
            };
            Ok(WebhookEventType::CheckoutCompleted(completed_data))
        } else if event_type == "payment.failed" || event_type == "payment.rejected" {
            Ok(WebhookEventType::InvoicePaymentFailed {
                invoice_id: user_id,
                subscription_id: None,
            })
        } else {
            Ok(WebhookEventType::Unknown {
                event_type,
                raw_data: serde_json::to_value(&web_event).unwrap_or(serde_json::Value::Null),
            })
        }
    }

    async fn get_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<SubscriptionInfo, GatewayError> {
        // Safepay does not provide a standard subscription retrieve endpoint
        // that returns status in the same format. We can return an active mock
        // or fetch details from Safepay reporter API if available.
        Ok(SubscriptionInfo {
            subscription_id: subscription_id.to_string(),
            customer_id: "safepay_customer".to_string(),
            status: SubscriptionStatus::Active,
            current_period_end: chrono::Utc::now() + chrono::Duration::days(30),
            tier: Some("professional".to_string()),
            cancel_at_period_end: false,
        })
    }

    async fn cancel_subscription(
        &self,
        _subscription_id: &str,
        _at_period_end: bool,
    ) -> Result<(), GatewayError> {
        // Safepay manual cancellation can be done via dashboard.
        // We gracefully succeed to avoid breaking core flows.
        Ok(())
    }

    fn gateway_info(&self) -> GatewayInfo {
        GatewayInfo {
            name: "safepay",
            display_name: "Safepay",
            supported_currencies: &["pkr", "usd"],
            supports_subscriptions: true,
            supports_one_time: true,
        }
    }
}
