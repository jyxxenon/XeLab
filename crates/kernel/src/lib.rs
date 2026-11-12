pub mod account_recovery;
pub mod admission;
pub mod api;
pub mod artifact;
pub mod auth;
pub mod backup_repository;
pub mod backups;
pub mod blobs;
pub mod broker;
pub(crate) mod broker_query;
mod broker_queue;
mod compact_http;
mod compact_rpc;
pub mod config;
pub mod contracts;
pub mod controller;
pub mod db;
pub mod dependencies;
pub mod deployments;
pub mod error;
pub(crate) mod event_streams;
pub mod events;
pub mod host;
pub mod host_blobs;
pub(crate) mod host_calls;
pub(crate) mod host_events;
pub mod http_contracts;
pub mod identity;
mod maintenance;
pub mod migration_rpc;
pub mod oauth;
pub mod offline;
pub(crate) mod plugin_catalog;
pub mod plugin_http;
pub mod plugin_http_gateway;
pub mod policy;
pub mod recovery;
pub mod restores;
pub mod runtime;
pub mod schema_jobs;
pub mod secrets;
pub(crate) mod skill_streams;
pub mod skills;
pub mod storage;
mod tasks;
pub mod tls;
pub mod ui;
pub mod upgrades;
pub mod volumes;
pub mod webui;
mod workflows;

#[allow(clippy::result_large_err)] // Generated Tonic service signatures use tonic::Status.
pub mod rpc {
    tonic::include_proto!("xelab.v1");
}

pub const SPEC_VERSION: &str = "2.8.0";

/// Select the same crypto provider in every binary when TLS dependencies enable multiple providers.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub mod oauth_http;
mod trusted_auth;
