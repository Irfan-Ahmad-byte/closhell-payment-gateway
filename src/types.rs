use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ── Enums ────────────────────────────────────────────

/// Billing interval for subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionInterval {
    Monthly,
    Yearly,
}

impl SubscriptionInterval {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "yearly" | "year" | "annual" => SubscriptionInterval::Yearly,
            _ => SubscriptionInterval::Monthly,
        }
    }
}

/// Currency codes supported by the gateway interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Currency {
    USD,
    EUR,
    GBP,
    PKR,
    INR,
    CAD,
    AUD,
    Other(String),
}

impl Default for Currency {
    fn default() -> Self {
        Currency::USD
    }
}

impl Currency {
    pub fn as_str(&self) -> &str {
        match self {
            Currency::USD => "usd",
            Currency::EUR => "eur",
            Currency::GBP => "gbp",
            Currency::PKR => "pkr",
            Currency::INR => "inr",
            Currency::CAD => "cad",
            Currency::AUD => "aud",
            Currency::Other(s) => s.as_str(),
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "usd" => Currency::USD,
            "eur" => Currency::EUR,
            "gbp" => Currency::GBP,
            "pkr" => Currency::PKR,
            "inr" => Currency::INR,
            "cad" => Currency::CAD,
            "aud" => Currency::AUD,
            other => Currency::Other(other.to_string()),
        }
    }
}

/// Subscription status values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    PastDue,
    Trialing,
    Expired,
    Cancelled,
    Incomplete,
    Unknown(String),
}

impl SubscriptionStatus {
    pub fn as_str(&self) -> &str {
        match self {
            SubscriptionStatus::Active => "active",
            SubscriptionStatus::PastDue => "past_due",
            SubscriptionStatus::Trialing => "trialing",
            SubscriptionStatus::Expired => "expired",
            SubscriptionStatus::Cancelled => "cancelled",
            SubscriptionStatus::Incomplete => "incomplete",
            SubscriptionStatus::Unknown(s) => s.as_str(),
        }
    }
}

// ── Checkout ─────────────────────────────────────────

/// Parameters for creating a checkout session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutParams {
    /// Customer's email address
    pub customer_email: String,
    /// Optional existing customer ID on the gateway
    pub customer_id: Option<String>,
    /// Display name of the plan/product
    pub plan_name: String,
    /// Internal tier identifier
    pub tier: String,
    /// Billing interval
    pub interval: SubscriptionInterval,
    /// Number of seats/licenses
    pub seats: u32,
    /// Unit amount in the smallest currency unit (e.g., cents for USD)
    pub unit_amount: i64,
    /// Currency for the transaction
    pub currency: Currency,
    /// URL to redirect after successful payment
    pub success_url: String,
    /// URL to redirect after cancelled payment
    pub cancel_url: String,
    /// A reference ID to identify the customer in your system
    pub client_reference_id: String,
    /// Arbitrary metadata to attach to the checkout
    pub metadata: HashMap<String, String>,
}

/// Result of creating a checkout session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutResult {
    /// The URL to redirect the customer to for payment
    pub checkout_url: String,
    /// The gateway that processed this checkout (e.g., "stripe")
    pub gateway: String,
    /// The gateway's session/checkout ID
    pub session_id: String,
}

// ── Webhook ──────────────────────────────────────────

/// Headers extracted from an incoming webhook request.
#[derive(Debug, Clone)]
pub struct WebhookHeaders {
    /// Gateway-specific signature header value
    pub signature: String,
    /// Optional signature version/key identifier
    pub signature_key: Option<String>,
    /// Raw header map for gateway-specific needs
    pub raw: Vec<(String, String)>,
}

impl WebhookHeaders {
    /// Create from a signature header value.
    pub fn new(signature: impl Into<String>) -> Self {
        WebhookHeaders {
            signature: signature.into(),
            signature_key: None,
            raw: Vec::new(),
        }
    }

    /// Get a specific header value by name (case-insensitive).
    pub fn get(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.raw
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }
}

/// Data extracted from a `checkout.session.completed` webhook event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutCompletedData {
    /// Gateway's session/checkout ID
    pub session_id: String,
    /// Gateway's customer ID
    pub customer_id: Option<String>,
    /// Gateway's subscription ID (if mode=subscription)
    pub subscription_id: Option<String>,
    /// Total amount in smallest currency unit (e.g., cents)
    pub amount_total: i64,
    /// Currency code
    pub currency: String,
    /// Plan tier from metadata
    pub tier: String,
    /// Billing interval from metadata
    pub interval: String,
    /// Your system's user/client reference ID
    pub client_reference_id: Option<String>,
    /// Number of seats from metadata
    pub seats: Option<u32>,
    /// All metadata attached to the checkout
    pub metadata: HashMap<String, String>,
}

/// Data extracted from a `customer.subscription.deleted` webhook event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionDeletedData {
    /// Gateway's subscription ID that was deleted/cancelled
    pub subscription_id: String,
}

/// Unified webhook event types that all gateways should map to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebhookEventType {
    /// A checkout session was completed successfully
    CheckoutCompleted(CheckoutCompletedData),
    /// A subscription was deleted/cancelled
    SubscriptionDeleted(SubscriptionDeletedData),
    /// A subscription was updated (e.g., plan change)
    SubscriptionUpdated {
        subscription_id: String,
        status: String,
    },
    /// An invoice payment succeeded
    InvoicePaid {
        invoice_id: String,
        subscription_id: Option<String>,
        amount_paid: i64,
        currency: String,
    },
    /// An invoice payment failed
    InvoicePaymentFailed {
        invoice_id: String,
        subscription_id: Option<String>,
    },
    /// An unrecognized event (gateway-specific, forwarded as raw data)
    Unknown {
        event_type: String,
        raw_data: serde_json::Value,
    },
}

// ── Subscription ─────────────────────────────────────

/// Information about a subscription retrieved from the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    /// Gateway's subscription ID
    pub subscription_id: String,
    /// Customer ID on the gateway
    pub customer_id: String,
    /// Current status
    pub status: SubscriptionStatus,
    /// When the current period ends
    pub current_period_end: chrono::DateTime<chrono::Utc>,
    /// Plan/product tier
    pub tier: Option<String>,
    /// Whether it will auto-renew
    pub cancel_at_period_end: bool,
}

// ── Gateway Info ─────────────────────────────────────

/// Information about a payment gateway implementation.
#[derive(Debug, Clone)]
pub struct GatewayInfo {
    /// Unique identifier for this gateway (e.g., "stripe", "payfast")
    pub name: &'static str,
    /// Human-readable display name (e.g., "Stripe", "PayFast")
    pub display_name: &'static str,
    /// Supported currencies
    pub supported_currencies: &'static [&'static str],
    /// Whether this gateway supports subscription mode
    pub supports_subscriptions: bool,
    /// Whether this gateway supports one-time payments
    pub supports_one_time: bool,
}
