//! Binds DNS resolutions to the outbound flows that (plausibly) used them.
//!
//! A `EventKind::DnsQuery` event carries the resolved IPs in its
//! `response_ips` attribute (comma-joined, see
//! `omnisec-ncer-parse-net::dns_query_event`). A `EventKind::FlowSummary`
//! event carries its destination as `dst` (`"ip:port"`, see
//! `omnisec-ncer-parse-net::flow_summary_event`). This module binds a flow to
//! the most recent preceding DNS resolution whose response included the
//! flow's destination IP, within `window` — the same "nearest preceding
//! cause within a window" shape as [`crate::effect_binder`], just keyed on IP
//! membership instead of an exact `(method, url)` match.
//!
//! A flow with no such resolution is an unbound flow: a connection we cannot
//! explain from any DNS lookup we observed (e.g. a hardcoded IP, or DNS
//! resolved outside the capture window). A DNS resolution matched by zero
//! flows is an unresolved query: we looked a name up but never actually used
//! any of the answers — an information-dimension discrepancy either way.
//!
//! IPv6 destinations are not matched: `DnsQueryCapture::response_ips` is
//! `Vec<Ipv4Addr>` only (see `omnisec-mitm::capture`), so an IPv6 flow can
//! never have a matching DNS event and always counts as unbound.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use omnisec_ncer_types::{EventKind, TypedEvent};

/// A [`TypedEvent::id`] value, referenced without borrowing the event itself.
pub type EventId = String;

/// Result of [`bind_dns_flow`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsFlowBindingResult {
    /// `(dns_query_id, flow_id)` pairs: a flow whose destination IP appeared
    /// in a preceding DNS resolution's answers, within the window.
    pub bound_pairs: Vec<(EventId, EventId)>,
    /// Flows with no explaining DNS resolution within the window.
    pub unbound_flows: Vec<EventId>,
    /// DNS resolutions matched by zero flows.
    pub unresolved_queries: Vec<EventId>,
}

/// Binds `EventKind::FlowSummary` events to the `EventKind::DnsQuery`
/// events whose answers plausibly caused them, within `window`.
///
/// Mirrors [`crate::effect_binder::bind_effects`]'s semantics: each flow
/// binds to at most one DNS resolution (the nearest preceding one that
/// resolved its destination IP); each DNS resolution can back multiple
/// flows (a single lookup's answer can be dialed more than once).
pub fn bind_dns_flow(events: &[TypedEvent], window: Duration) -> DnsFlowBindingResult {
    let window_ms = window.as_millis() as u64;

    let mut queries: Vec<&TypedEvent> = events
        .iter()
        .filter(|e| e.kind == EventKind::DnsQuery)
        .collect();
    queries.sort_by(|left, right| {
        left.observed_at_ms
            .cmp(&right.observed_at_ms)
            .then_with(|| left.id.cmp(&right.id))
    });

    let mut flows: Vec<&TypedEvent> = events
        .iter()
        .filter(|e| e.kind == EventKind::FlowSummary)
        .collect();
    flows.sort_by(|left, right| {
        left.observed_at_ms
            .cmp(&right.observed_at_ms)
            .then_with(|| left.id.cmp(&right.id))
    });

    // Index queries by resolved IP -> observed_at_ms -> {query ids}, so each
    // flow resolves its nearest-preceding-within-window candidate via a
    // predecessor lookup instead of scanning every query.
    let mut by_ip: HashMap<String, BTreeMap<u64, HashSet<&str>>> = HashMap::new();
    for query in &queries {
        for ip in response_ips(query) {
            by_ip
                .entry(ip)
                .or_default()
                .entry(query.observed_at_ms)
                .or_default()
                .insert(query.id.as_str());
        }
    }

    let mut used_query_ids: HashSet<&str> = HashSet::new();
    let mut bound_pairs = Vec::new();
    let mut unbound_flows = Vec::new();

    for flow in &flows {
        let flow_time = flow.observed_at_ms;

        let candidate = dst_ip(flow)
            .and_then(|ip| by_ip.get(&ip))
            .and_then(|by_time| {
                let (&ts, ids) = by_time.range(..=flow_time).next_back()?;
                if flow_time - ts > window_ms {
                    return None;
                }
                ids.iter().max().copied()
            });

        match candidate {
            Some(id) => {
                used_query_ids.insert(id);
                bound_pairs.push((id.to_string(), flow.id.clone()));
            }
            None => unbound_flows.push(flow.id.clone()),
        }
    }

    let unresolved_queries = queries
        .iter()
        .filter(|q| !used_query_ids.contains(q.id.as_str()))
        .map(|q| q.id.clone())
        .collect();

    DnsFlowBindingResult {
        bound_pairs,
        unbound_flows,
        unresolved_queries,
    }
}

/// Parses a DNS query event's comma-joined `response_ips` attribute back
/// into individual IP strings. Empty for a query with no resolved IPs.
fn response_ips(event: &TypedEvent) -> Vec<String> {
    event
        .attributes
        .get("response_ips")
        .map(|s| {
            s.split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Extracts the destination IP from a flow event's `dst` attribute
/// (`"ip:port"`), returning `None` if the attribute is missing or malformed.
fn dst_ip(event: &TypedEvent) -> Option<String> {
    let dst = event.attributes.get("dst")?;
    let (ip, _port) = dst.rsplit_once(':')?;
    Some(ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn dns_event(
        id: &str,
        observed_at_ms: u64,
        query_name: &str,
        response_ips: &[&str],
    ) -> TypedEvent {
        let mut attributes = BTreeMap::new();
        attributes.insert("query_name".to_string(), query_name.to_string());
        attributes.insert("response_ips".to_string(), response_ips.join(","));
        TypedEvent {
            id: id.to_string(),
            sensor_id: "mitm-local".to_string(),
            kind: EventKind::DnsQuery,
            observed_at_ms,
            subjects: vec![query_name.to_string()],
            description: format!("DNS query for {query_name}"),
            score: 1.0,
            attributes,
            evidence_refs: vec![],
        }
    }

    fn flow_event(id: &str, observed_at_ms: u64, dst_ip: &str) -> TypedEvent {
        let mut attributes = BTreeMap::new();
        attributes.insert("src".to_string(), "192.168.1.2:51234".to_string());
        attributes.insert("dst".to_string(), format!("{dst_ip}:443"));
        TypedEvent {
            id: id.to_string(),
            sensor_id: "mitm-local".to_string(),
            kind: EventKind::FlowSummary,
            observed_at_ms,
            subjects: vec![format!("192.168.1.2:51234 -> {dst_ip}:443")],
            description: "flow".to_string(),
            score: 1.0,
            attributes,
            evidence_refs: vec![],
        }
    }

    #[test]
    fn flow_binds_to_preceding_dns_resolution_within_window() {
        let events = vec![
            dns_event("dns-1", 1_000, "example.com", &["93.184.216.34"]),
            flow_event("flow-1", 1_100, "93.184.216.34"),
        ];
        let result = bind_dns_flow(&events, Duration::from_secs(5));
        assert_eq!(
            result.bound_pairs,
            vec![("dns-1".to_string(), "flow-1".to_string())]
        );
        assert!(result.unbound_flows.is_empty());
        assert!(result.unresolved_queries.is_empty());
    }

    #[test]
    fn flow_outside_window_is_unbound_and_query_is_unresolved() {
        let events = vec![
            dns_event("dns-1", 1_000, "example.com", &["93.184.216.34"]),
            flow_event("flow-1", 10_000, "93.184.216.34"),
        ];
        let result = bind_dns_flow(&events, Duration::from_secs(1));
        assert!(result.bound_pairs.is_empty());
        assert_eq!(result.unbound_flows, vec!["flow-1".to_string()]);
        assert_eq!(result.unresolved_queries, vec!["dns-1".to_string()]);
    }

    #[test]
    fn flow_with_no_matching_ip_is_unbound() {
        let events = vec![
            dns_event("dns-1", 1_000, "example.com", &["93.184.216.34"]),
            flow_event("flow-1", 1_100, "1.2.3.4"),
        ];
        let result = bind_dns_flow(&events, Duration::from_secs(5));
        assert!(result.bound_pairs.is_empty());
        assert_eq!(result.unbound_flows, vec!["flow-1".to_string()]);
        assert_eq!(result.unresolved_queries, vec!["dns-1".to_string()]);
    }

    #[test]
    fn query_never_dialed_is_unresolved() {
        let events = vec![dns_event("dns-1", 1_000, "example.com", &["93.184.216.34"])];
        let result = bind_dns_flow(&events, Duration::from_secs(5));
        assert!(result.bound_pairs.is_empty());
        assert_eq!(result.unresolved_queries, vec!["dns-1".to_string()]);
    }

    #[test]
    fn flow_with_no_dns_at_all_is_unbound() {
        let events = vec![flow_event("flow-1", 1_000, "93.184.216.34")];
        let result = bind_dns_flow(&events, Duration::from_secs(5));
        assert_eq!(result.unbound_flows, vec!["flow-1".to_string()]);
    }

    #[test]
    fn one_resolution_can_back_multiple_flows() {
        let events = vec![
            dns_event("dns-1", 1_000, "example.com", &["93.184.216.34"]),
            flow_event("flow-1", 1_100, "93.184.216.34"),
            flow_event("flow-2", 1_200, "93.184.216.34"),
        ];
        let result = bind_dns_flow(&events, Duration::from_secs(5));
        assert_eq!(result.bound_pairs.len(), 2);
        assert!(result.unresolved_queries.is_empty());
    }

    #[test]
    fn multiple_response_ips_all_match() {
        let events = vec![
            dns_event(
                "dns-1",
                1_000,
                "example.com",
                &["93.184.216.34", "93.184.216.35"],
            ),
            flow_event("flow-1", 1_100, "93.184.216.35"),
        ];
        let result = bind_dns_flow(&events, Duration::from_secs(5));
        assert_eq!(
            result.bound_pairs,
            vec![("dns-1".to_string(), "flow-1".to_string())]
        );
    }

    #[test]
    fn non_dns_or_flow_events_are_ignored() {
        let mut attrs = BTreeMap::new();
        attrs.insert("method".to_string(), "GET".to_string());
        let http_event = TypedEvent {
            id: "http-1".to_string(),
            sensor_id: "mitm-local".to_string(),
            kind: EventKind::HttpRequest,
            observed_at_ms: 0,
            subjects: vec![],
            description: "GET /".to_string(),
            score: 0.0,
            attributes: attrs.clone(),
            evidence_refs: vec![],
        };
        let result = bind_dns_flow(&[http_event], Duration::from_secs(5));
        assert_eq!(result, DnsFlowBindingResult::default());
    }

    #[test]
    fn empty_input_produces_empty_result() {
        let result = bind_dns_flow(&[], Duration::from_secs(5));
        assert_eq!(result, DnsFlowBindingResult::default());
    }
}
