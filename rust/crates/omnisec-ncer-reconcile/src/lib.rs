//! Causal reconciliation for the NCER (Network Claim-Evidence Reconciliation)
//! layer.
//!
//! An unbound effect — a response, callback, or answer with nothing in our
//! observation stream that explains it — is a finding seed: "something
//! happened on the network that nothing we observed accounts for." This
//! crate's job is to identify those by binding effects to the causes that
//! plausibly produced them, so later phases can treat what's left over as
//! evidence worth investigating.
//!
//! [`effect_binder`] binds HTTP responses to the requests that caused them.
//! [`authority_binder`] binds observed sensitive actions to the permissions
//! granted to the same subject. [`dns_flow_binder`] binds DNS resolutions to
//! the outbound flows that used them. [`scoring`] turns all three binding
//! results into a single [`scoring::DiscrepancyVector`].

/// Binds observed authority-exercising actions to granted permissions.
pub mod authority_binder;
/// Binds DNS resolutions to the outbound flows that used them.
pub mod dns_flow_binder;
/// Binds effects (e.g. HTTP responses) back to the causes that produced them.
pub mod effect_binder;
/// Stores and verifies raw reconciliation input in a content-addressed evidence store.
pub mod evidence;
/// Turns binding results into a [`scoring::DiscrepancyVector`].
pub mod scoring;

pub use authority_binder::{AuthorityBindingResult, bind_authority};
pub use dns_flow_binder::{DnsFlowBindingResult, bind_dns_flow};
pub use effect_binder::{BindingResult, EventId, bind_effects};
pub use evidence::store_and_verify;
pub use scoring::{DiscrepancyVector, score_all, score_authority, score_causal, score_dns_flow};
