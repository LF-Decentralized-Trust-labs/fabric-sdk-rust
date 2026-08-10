//! Client for the operations service exposed by Fabric peers and orderers.
//!
//! Native-only (feature `client`). The operations service is an HTTP endpoint
//! (default ports 9443/9444 in the test network) serving health checks,
//! version info, log-level management and Prometheus metrics.

mod client;
pub use client::{HealthStatus, LogSpec, OperationsClient, OperationsClientBuilder};
