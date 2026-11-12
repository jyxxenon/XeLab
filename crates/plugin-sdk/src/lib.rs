//! Rust bindings and workload mTLS for XeLab ordinary plugins.

#[allow(clippy::result_large_err)] // Generated Tonic service signatures use tonic::Status.
pub mod rpc {
    tonic::include_proto!("xelab.v1");
}

pub mod transport;
