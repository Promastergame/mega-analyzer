//! Binds effects (e.g. HTTP responses) back to the causes (e.g. HTTP
//! requests) that plausibly produced them, within a time window.
//!
//! Today this only handles HTTP request/response binding, since that's the
//! only cause/effect pair `omnisec-ncer-parse-net` currently emits as two
//! separate [`TypedEvent`]s (`EventKind::HttpRequest` /
//! `EventKind::HttpResponse`, correlated by the `method`/`url` attributes —
//! see `omnisec-ncer-parse-net`'s `http_response_event`). DNS query/answer
//! binding by query name is not implemented: `omnisec-mitm` captures a DNS
//! query and its answer as a single `EventKind::DnsQuery` event today, so
//! there is no separate answer event to bind against yet. When one exists,
//! it can be matched the same way this binds HTTP.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use omnisec_ncer_types::{EventKind, TypedEvent};

/// A [`TypedEvent::id`] value, referenced without borrowing the event itself.
pub type EventId = String;

/// Result of [`bind_effects`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BindingResult {
    /// `(request_id, response_id)` pairs bound to each other.
    pub bound_pairs: Vec<(EventId, EventId)>,
    /// Effects (e.g. responses) with no matching cause within the window —
    /// a finding seed: something we observed that nothing else explains.
    pub unbound_effects: Vec<EventId>,
    /// Requests that never got a matching response within the window.
    pub orphan_requests: Vec<EventId>,
}

/// Binds effects to the causes that plausibly produced them within `window`.
///
/// `events` need not already be sorted by `observed_at_ms`; this function
/// sorts internally, so passing a time-ordered slice (the common case) is
/// just as valid as an unordered one.
///
/// Binding logic (HTTP only, see module docs): a response is matched to the
/// request with the same `method`+`url` attributes whose timestamp is the
/// closest one at or before the response's timestamp, and within `window`
/// of it. Each request binds to at most one response and vice versa. A
/// response with no eligible request is an unbound effect; a request with
/// no eligible response is an orphan request.
///
/// Requests are indexed by `(method, url)` into a per-key `observed_at_ms ->
/// {ids}` map, so each response resolves its nearest-preceding-within-window
/// candidate via a predecessor lookup (`O(log n)`) instead of scanning every
/// request (`O(n)`); this keeps the whole function `O(n log n)` rather than
/// `O(requests * responses)`, which matters once a capture reaches thousands
/// of events.
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
/// use std::time::Duration;
/// use omnisec_ncer_types::{EventKind, TypedEvent};
/// use omnisec_ncer_reconcile::bind_effects;
///
/// let mut attrs = BTreeMap::new();
/// attrs.insert("method".to_string(), "GET".to_string());
/// attrs.insert("url".to_string(), "https://example.com/".to_string());
///
/// let req = TypedEvent {
///     id: "req-1".to_string(),
///     sensor_id: "test".to_string(),
///     kind: EventKind::HttpRequest,
///     observed_at_ms: 1000,
///     subjects: vec![],
///     description: "request".to_string(),
///     score: 0.0,
///     attributes: attrs.clone(),
///     evidence_refs: vec![],
/// };
/// let resp = TypedEvent {
///     id: "resp-1".to_string(),
///     sensor_id: "test".to_string(),
///     kind: EventKind::HttpResponse,
///     observed_at_ms: 1050,
///     subjects: vec![],
///     description: "response".to_string(),
///     score: 0.0,
///     attributes: attrs,
///     evidence_refs: vec![],
/// };
///
/// let result = bind_effects(&[req, resp], Duration::from_secs(5));
/// assert_eq!(result.bound_pairs, vec![("req-1".to_string(), "resp-1".to_string())]);
/// ```
pub fn bind_effects(events: &[TypedEvent], window: Duration) -> BindingResult {
    let window_ms = window.as_millis() as u64;

    let mut requests: Vec<&TypedEvent> = events
        .iter()
        .filter(|e| e.kind == EventKind::HttpRequest)
        .collect();
    requests.sort_by(|left, right| {
        left.observed_at_ms
            .cmp(&right.observed_at_ms)
            .then_with(|| left.id.cmp(&right.id))
    });

    let mut responses: Vec<&TypedEvent> = events
        .iter()
        .filter(|e| e.kind == EventKind::HttpResponse)
        .collect();
    responses.sort_by(|left, right| {
        left.observed_at_ms
            .cmp(&right.observed_at_ms)
            .then_with(|| left.id.cmp(&right.id))
    });

    // Requests with no (method, url) key can never match any response (see
    // http_key's doc comment), so they're left out of the index entirely —
    // they fall out as orphans in the final pass below, same as before.
    let mut by_key: HashMap<(&str, &str), BTreeMap<u64, HashSet<&str>>> = HashMap::new();
    for req in &requests {
        if let Some(key) = http_key(req) {
            by_key
                .entry(key)
                .or_default()
                .entry(req.observed_at_ms)
                .or_default()
                .insert(req.id.as_str());
        }
    }

    let mut bound_request_ids: HashSet<&str> = HashSet::new();
    let mut bound_pairs = Vec::new();
    let mut unbound_effects = Vec::new();

    for response in &responses {
        let response_time = response.observed_at_ms;

        let candidate = http_key(response)
            .and_then(|key| by_key.get_mut(&key))
            .and_then(|by_time| {
                let (&ts, ids) = by_time.range_mut(..=response_time).next_back()?;
                if response_time - ts > window_ms {
                    return None;
                }
                // Tie-break identical to the original max_by(time, then id):
                // among candidates at the winning (highest eligible) timestamp,
                // take the lexicographically greatest id.
                let id = *ids.iter().max()?;
                ids.remove(id);
                if ids.is_empty() {
                    by_time.remove(&ts);
                }
                Some(id)
            });

        match candidate {
            Some(id) => {
                bound_request_ids.insert(id);
                bound_pairs.push((id.to_string(), response.id.clone()));
            }
            None => unbound_effects.push(response.id.clone()),
        }
    }

    let orphan_requests = requests
        .iter()
        .filter(|req| !bound_request_ids.contains(req.id.as_str()))
        .map(|req| req.id.clone())
        .collect();

    BindingResult {
        bound_pairs,
        unbound_effects,
        orphan_requests,
    }
}

/// `(method, url)` correlation key for an HTTP request or response event.
/// `None` if either attribute is missing (e.g. a response whose originating
/// request was never observed — see `omnisec-mitm`'s `HttpResponseCapture`).
fn http_key(event: &TypedEvent) -> Option<(&str, &str)> {
    let method = event.attributes.get("method")?;
    let url = event.attributes.get("url")?;
    Some((method.as_str(), url.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn http_event(
        id: &str,
        kind: EventKind,
        observed_at_ms: u64,
        method: &str,
        url: &str,
    ) -> TypedEvent {
        let mut attributes = BTreeMap::new();
        attributes.insert("method".to_string(), method.to_string());
        attributes.insert("url".to_string(), url.to_string());
        TypedEvent {
            id: id.to_string(),
            sensor_id: "mitm-local".to_string(),
            kind,
            observed_at_ms,
            subjects: vec![url.to_string()],
            description: format!("{method} {url}"),
            score: 1.0,
            attributes,
            evidence_refs: vec![],
        }
    }

    fn request(id: &str, observed_at_ms: u64, method: &str, url: &str) -> TypedEvent {
        http_event(id, EventKind::HttpRequest, observed_at_ms, method, url)
    }

    fn response(id: &str, observed_at_ms: u64, method: &str, url: &str) -> TypedEvent {
        http_event(id, EventKind::HttpResponse, observed_at_ms, method, url)
    }

    /// A response with no method/url attributes at all, as produced when
    /// `omnisec-mitm` never observed the originating request.
    fn response_without_key(id: &str, observed_at_ms: u64, status: u16) -> TypedEvent {
        let mut attributes = BTreeMap::new();
        attributes.insert("status".to_string(), status.to_string());
        TypedEvent {
            id: id.to_string(),
            sensor_id: "mitm-local".to_string(),
            kind: EventKind::HttpResponse,
            observed_at_ms,
            subjects: vec![],
            description: format!("HTTP response {status}"),
            score: 1.0,
            attributes,
            evidence_refs: vec![],
        }
    }

    #[test]
    fn matches_a_request_to_its_response_within_the_window() {
        let events = vec![
            request("req-1", 1_000, "GET", "/index.html"),
            response("resp-1", 1_050, "GET", "/index.html"),
        ];

        let result = bind_effects(&events, Duration::from_millis(500));

        assert_eq!(
            result.bound_pairs,
            vec![("req-1".to_string(), "resp-1".to_string())]
        );
        assert!(result.unbound_effects.is_empty());
        assert!(result.orphan_requests.is_empty());
    }

    #[test]
    fn request_outside_the_window_is_an_orphan_and_response_is_unbound() {
        let events = vec![
            request("req-1", 1_000, "GET", "/index.html"),
            response("resp-1", 5_000, "GET", "/index.html"),
        ];

        let result = bind_effects(&events, Duration::from_millis(500));

        assert!(result.bound_pairs.is_empty());
        assert_eq!(result.unbound_effects, vec!["resp-1".to_string()]);
        assert_eq!(result.orphan_requests, vec!["req-1".to_string()]);
    }

    #[test]
    fn request_with_no_response_at_all_is_an_orphan() {
        let events = vec![request("req-1", 1_000, "GET", "/index.html")];

        let result = bind_effects(&events, Duration::from_millis(500));

        assert!(result.bound_pairs.is_empty());
        assert!(result.unbound_effects.is_empty());
        assert_eq!(result.orphan_requests, vec!["req-1".to_string()]);
    }

    #[test]
    fn response_with_no_matching_request_is_an_unbound_effect() {
        let events = vec![response("resp-1", 1_000, "GET", "/index.html")];

        let result = bind_effects(&events, Duration::from_millis(500));

        assert!(result.bound_pairs.is_empty());
        assert_eq!(result.unbound_effects, vec!["resp-1".to_string()]);
        assert!(result.orphan_requests.is_empty());
    }

    #[test]
    fn response_missing_method_or_url_attributes_is_an_unbound_effect() {
        let events = vec![
            request("req-1", 1_000, "GET", "/index.html"),
            response_without_key("resp-1", 1_050, 200),
        ];

        let result = bind_effects(&events, Duration::from_millis(500));

        assert!(result.bound_pairs.is_empty());
        assert_eq!(result.unbound_effects, vec!["resp-1".to_string()]);
        assert_eq!(result.orphan_requests, vec!["req-1".to_string()]);
    }

    #[test]
    fn different_url_does_not_match_even_within_the_window() {
        let events = vec![
            request("req-1", 1_000, "GET", "/a"),
            response("resp-1", 1_050, "GET", "/b"),
        ];

        let result = bind_effects(&events, Duration::from_millis(500));

        assert!(result.bound_pairs.is_empty());
        assert_eq!(result.unbound_effects, vec!["resp-1".to_string()]);
        assert_eq!(result.orphan_requests, vec!["req-1".to_string()]);
    }

    #[test]
    fn different_method_does_not_match_even_with_the_same_url() {
        let events = vec![
            request("req-1", 1_000, "GET", "/index.html"),
            response("resp-1", 1_050, "POST", "/index.html"),
        ];

        let result = bind_effects(&events, Duration::from_millis(500));

        assert!(result.bound_pairs.is_empty());
        assert_eq!(result.unbound_effects, vec!["resp-1".to_string()]);
        assert_eq!(result.orphan_requests, vec!["req-1".to_string()]);
    }

    #[test]
    fn two_requests_for_the_same_url_each_bind_to_the_nearest_preceding_response() {
        let events = vec![
            request("req-1", 1_000, "GET", "/index.html"),
            response("resp-1", 1_050, "GET", "/index.html"),
            request("req-2", 2_000, "GET", "/index.html"),
            response("resp-2", 2_050, "GET", "/index.html"),
        ];

        let result = bind_effects(&events, Duration::from_millis(500));

        let mut bound = result.bound_pairs.clone();
        bound.sort();
        assert_eq!(
            bound,
            vec![
                ("req-1".to_string(), "resp-1".to_string()),
                ("req-2".to_string(), "resp-2".to_string()),
            ]
        );
        assert!(result.unbound_effects.is_empty());
        assert!(result.orphan_requests.is_empty());
    }

    #[test]
    fn unordered_input_is_handled_the_same_as_time_ordered_input() {
        let events = vec![
            response("resp-1", 1_050, "GET", "/index.html"),
            request("req-1", 1_000, "GET", "/index.html"),
        ];

        let result = bind_effects(&events, Duration::from_millis(500));

        assert_eq!(
            result.bound_pairs,
            vec![("req-1".to_string(), "resp-1".to_string())]
        );
    }

    #[test]
    fn mixed_scenario_classifies_matched_orphan_and_unbound_correctly() {
        let events = vec![
            // Matched pair.
            request("req-matched", 1_000, "GET", "/index.html"),
            response("resp-matched", 1_020, "GET", "/index.html"),
            // Deliberate orphan: never gets a response.
            request("req-orphan", 2_000, "POST", "/login"),
            // Deliberate unbound effect: no request ever asked for this URL.
            response("resp-unbound", 3_000, "GET", "/unexpected.js"),
        ];

        let result = bind_effects(&events, Duration::from_millis(500));

        assert_eq!(
            result.bound_pairs,
            vec![("req-matched".to_string(), "resp-matched".to_string())]
        );
        assert_eq!(result.unbound_effects, vec!["resp-unbound".to_string()]);
        assert_eq!(result.orphan_requests, vec!["req-orphan".to_string()]);
    }

    #[test]
    fn empty_input_produces_empty_result() {
        let result = bind_effects(&[], Duration::from_secs(1));
        assert_eq!(result, BindingResult::default());
    }

    /// Two requests for the same key at the *exact* same timestamp is the
    /// edge case the indexed lookup has to get right: candidates at the
    /// winning timestamp bucket must still be tie-broken by the
    /// lexicographically greatest id, matching the original linear-scan
    /// max_by(time, then id) behavior.
    #[test]
    fn same_timestamp_candidates_tie_break_by_greatest_id() {
        let events = vec![
            request("req-a", 1_000, "GET", "/index.html"),
            request("req-b", 1_000, "GET", "/index.html"),
            response("resp-1", 1_010, "GET", "/index.html"),
        ];

        let result = bind_effects(&events, Duration::from_millis(500));

        assert_eq!(
            result.bound_pairs,
            vec![("req-b".to_string(), "resp-1".to_string())]
        );
        assert_eq!(result.orphan_requests, vec!["req-a".to_string()]);
    }

    /// A large capture with events spread across many distinct (method, url)
    /// keys, sized well beyond what an O(requests * responses) scan would
    /// comfortably handle in a unit test, to guard against a regression back
    /// to quadratic behavior.
    #[test]
    fn large_capture_across_many_keys_binds_correctly() {
        const N: u64 = 5_000;
        let mut events = Vec::with_capacity((N * 2) as usize);
        for i in 0..N {
            let url = format!("/resource/{i}");
            events.push(request(&format!("req-{i}"), i * 10, "GET", &url));
            events.push(response(&format!("resp-{i}"), i * 10 + 5, "GET", &url));
        }

        let result = bind_effects(&events, Duration::from_millis(500));

        assert_eq!(result.bound_pairs.len(), N as usize);
        assert!(result.unbound_effects.is_empty());
        assert!(result.orphan_requests.is_empty());
    }
}
