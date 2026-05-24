use std::collections::HashMap;
use std::sync::Arc;

use crate::error::GatewayError;
use crate::gateway_trait::PaymentGateway;
use crate::types::GatewayInfo;

/// Routes payment requests to the appropriate gateway.
///
/// Holds multiple gateway implementations and selects one based on
/// a gateway name (e.g., "stripe", "payfast") at runtime.
///
/// # Example
///
/// ```ignore
/// use closhell_payment_gateway::{GatewayRouter, StripeGateway};
///
/// let mut router = GatewayRouter::new();
/// router.register(StripeGateway::from_env());
///
/// let gateway = router.get("stripe").unwrap();
/// ```
#[derive(Clone)]
pub struct GatewayRouter {
    gateways: Arc<HashMap<String, Arc<dyn PaymentGateway>>>,
    default: String,
}

impl GatewayRouter {
    /// Create a new empty router with no gateways registered.
    /// You must call [`register`] before using it.
    pub fn new() -> Self {
        GatewayRouter {
            gateways: Arc::new(HashMap::new()),
            default: String::new(),
        }
    }

    /// Register a gateway implementation.
    ///
    /// The gateway's name (from [`PaymentGateway::gateway_info`]) is used
    /// as the key for routing.
    pub fn register(&mut self, gateway: impl PaymentGateway + 'static) {
        let info = gateway.gateway_info();
        let name = info.name.to_string();

        let gateways = Arc::make_mut(&mut self.gateways);
        gateways.insert(name.clone(), Arc::new(gateway));

        // Set first registered gateway as default
        if self.default.is_empty() {
            self.default = name;
        }
    }

    /// Set which gateway should be the default (used when no specific gateway
    /// is requested).
    pub fn set_default(&mut self, name: &str) {
        self.default = name.to_string();
    }

    /// Get a gateway by name. Returns `None` if the gateway is not registered.
    pub fn get(&self, name: &str) -> Option<&dyn PaymentGateway> {
        self.gateways.get(name).map(|g| g.as_ref())
    }

    /// Get the default gateway.
    pub fn default(&self) -> Result<&dyn PaymentGateway, GatewayError> {
        self.get(&self.default).ok_or_else(|| {
            GatewayError::GatewayNotConfigured {
                gateway: self.default.clone(),
            }
        })
    }

    /// Get a gateway by name, or fall back to the default.
    pub fn get_or_default(&self, name: Option<&str>) -> Result<&dyn PaymentGateway, GatewayError> {
        match name {
            Some(n) if !n.is_empty() => {
                self.get(n).ok_or_else(|| GatewayError::GatewayNotConfigured {
                    gateway: n.to_string(),
                })
            }
            _ => self.default(),
        }
    }

    /// List all registered gateway names and their info.
    pub fn list_gateways(&self) -> Vec<GatewayInfo> {
        self.gateways.values().map(|g| g.gateway_info()).collect()
    }

    /// Check if a gateway is registered.
    pub fn has(&self, name: &str) -> bool {
        self.gateways.contains_key(name)
    }

    /// Return the number of registered gateways.
    pub fn len(&self) -> usize {
        self.gateways.len()
    }

    /// Returns true if no gateways are registered.
    pub fn is_empty(&self) -> bool {
        self.gateways.is_empty()
    }
}

impl Default for GatewayRouter {
    fn default() -> Self {
        Self::new()
    }
}
