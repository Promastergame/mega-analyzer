//! Binds observed authority-exercising actions back to the permissions
//! granted to the same subject.
//!
//! This mirrors [`crate::effect_binder`]'s request/response binding, but the
//! correlation key is `(subject_id, permission)` instead of `(method, url)`,
//! and there is no time window: a permission grant is a standing fact for
//! the whole session, not a point-in-time cause that can go "stale" the way
//! an HTTP request does.
//!
//! `EventKind::AuthorityGrant` events are produced from an app's declared/
//! granted permissions (e.g. `AndroidManifest.xml`, `pkg/ncer/authority.go`'s
//! `FromAuthorityContextGranular`), one event per permission.
//! `EventKind::AuthorityObserved` events are produced from actions observed
//! during dynamic analysis (network connects, sensitive API calls), one
//! event per action, each carrying a `required_permission` attribute set
//! from a best-effort action-to-permission mapping
//! (`pkg/ncer/authority_mapping.go`). An observed action whose mapping is
//! unknown carries no `required_permission` attribute and is excluded from
//! binding entirely — it's neither authorized nor unauthorized, just
//! unclassifiable with today's mapping table.

use std::collections::{HashMap, HashSet};

use omnisec_ncer_types::{EventKind, TypedEvent};

/// A [`TypedEvent::id`] value, referenced without borrowing the event itself.
pub type EventId = String;

/// Result of [`bind_authority`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityBindingResult {
    /// `(grant_id, observed_id)` pairs: an observed action whose required
    /// permission was granted to the same subject.
    pub authorized: Vec<(EventId, EventId)>,
    /// Observed actions whose required permission has no matching grant for
    /// the same subject — an authority discrepancy: something was done that
    /// nothing we observed permits.
    pub unauthorized_observed: Vec<EventId>,
    /// Granted permissions never exercised by any observed action for the
    /// same subject — unused capability.
    pub unused_grants: Vec<EventId>,
}

/// Binds `EventKind::AuthorityObserved` events to the
/// `EventKind::AuthorityGrant` events that authorize them, by
/// `(subject_id, permission)`.
///
/// Observed actions with no `required_permission` attribute (unmapped
/// actions — see the module doc) are skipped entirely: they contribute to
/// neither `authorized` nor `unauthorized_observed`, since a missing mapping
/// is not evidence of anything.
///
/// A single grant can authorize multiple observed actions (the same
/// permission can back many actions); `unused_grants` only ever contains
/// grants matched by zero observed actions.
pub fn bind_authority(events: &[TypedEvent]) -> AuthorityBindingResult {
    let grants: Vec<&TypedEvent> = events
        .iter()
        .filter(|e| e.kind == EventKind::AuthorityGrant)
        .collect();
    let observed: Vec<&TypedEvent> = events
        .iter()
        .filter(|e| e.kind == EventKind::AuthorityObserved)
        .collect();

    let mut by_key: HashMap<(&str, &str), Vec<&TypedEvent>> = HashMap::new();
    for grant in &grants {
        if let Some(key) = grant_key(grant) {
            by_key.entry(key).or_default().push(grant);
        }
    }

    let mut used_grant_ids: HashSet<&str> = HashSet::new();
    let mut authorized = Vec::new();
    let mut unauthorized_observed = Vec::new();

    for obs in &observed {
        let Some(key) = observed_key(obs) else {
            continue;
        };

        match by_key.get(&key).and_then(|candidates| candidates.first()) {
            Some(grant) => {
                used_grant_ids.insert(grant.id.as_str());
                authorized.push((grant.id.clone(), obs.id.clone()));
            }
            None => unauthorized_observed.push(obs.id.clone()),
        }
    }

    let unused_grants = grants
        .iter()
        .filter(|grant| !used_grant_ids.contains(grant.id.as_str()))
        .map(|grant| grant.id.clone())
        .collect();

    AuthorityBindingResult {
        authorized,
        unauthorized_observed,
        unused_grants,
    }
}

/// `(subject_id, permission)` correlation key for an `AuthorityGrant` event.
/// `None` if either attribute is missing.
fn grant_key(event: &TypedEvent) -> Option<(&str, &str)> {
    let subject = event.attributes.get("subject_id")?;
    let permission = event.attributes.get("permission")?;
    Some((subject.as_str(), permission.as_str()))
}

/// `(subject_id, required_permission)` correlation key for an
/// `AuthorityObserved` event. `None` if either attribute is missing or
/// `required_permission` is empty (the action-to-permission mapping had no
/// entry for this action — see the module doc).
fn observed_key(event: &TypedEvent) -> Option<(&str, &str)> {
    let subject = event.attributes.get("subject_id")?;
    let permission = event.attributes.get("required_permission")?;
    if permission.is_empty() {
        return None;
    }
    Some((subject.as_str(), permission.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn grant(id: &str, subject: &str, permission: &str) -> TypedEvent {
        let mut attributes = BTreeMap::new();
        attributes.insert("subject_id".to_string(), subject.to_string());
        attributes.insert("permission".to_string(), permission.to_string());
        TypedEvent {
            id: id.to_string(),
            sensor_id: "manifest".to_string(),
            kind: EventKind::AuthorityGrant,
            observed_at_ms: 0,
            subjects: vec![subject.to_string()],
            description: format!("granted {permission}"),
            score: 0.0,
            attributes,
            evidence_refs: vec![],
        }
    }

    fn observed(id: &str, subject: &str, required_permission: Option<&str>) -> TypedEvent {
        let mut attributes = BTreeMap::new();
        attributes.insert("subject_id".to_string(), subject.to_string());
        if let Some(perm) = required_permission {
            attributes.insert("required_permission".to_string(), perm.to_string());
        }
        TypedEvent {
            id: id.to_string(),
            sensor_id: "sandbox".to_string(),
            kind: EventKind::AuthorityObserved,
            observed_at_ms: 1,
            subjects: vec![subject.to_string()],
            description: "observed action".to_string(),
            score: 0.0,
            attributes,
            evidence_refs: vec![],
        }
    }

    #[test]
    fn observed_action_with_matching_grant_is_authorized() {
        let events = vec![
            grant("grant-1", "com.example.app", "android.permission.INTERNET"),
            observed(
                "obs-1",
                "com.example.app",
                Some("android.permission.INTERNET"),
            ),
        ];
        let result = bind_authority(&events);
        assert_eq!(
            result.authorized,
            vec![("grant-1".to_string(), "obs-1".to_string())]
        );
        assert!(result.unauthorized_observed.is_empty());
        assert!(result.unused_grants.is_empty());
    }

    #[test]
    fn observed_action_with_no_grant_is_unauthorized() {
        let events = vec![observed(
            "obs-1",
            "com.example.app",
            Some("android.permission.CAMERA"),
        )];
        let result = bind_authority(&events);
        assert!(result.authorized.is_empty());
        assert_eq!(result.unauthorized_observed, vec!["obs-1".to_string()]);
    }

    #[test]
    fn observed_action_for_different_subject_does_not_match() {
        let events = vec![
            grant("grant-1", "com.example.app", "android.permission.INTERNET"),
            observed(
                "obs-1",
                "com.other.app",
                Some("android.permission.INTERNET"),
            ),
        ];
        let result = bind_authority(&events);
        assert!(result.authorized.is_empty());
        assert_eq!(result.unauthorized_observed, vec!["obs-1".to_string()]);
        assert_eq!(result.unused_grants, vec!["grant-1".to_string()]);
    }

    #[test]
    fn unmapped_observed_action_is_skipped_entirely() {
        let events = vec![
            grant("grant-1", "com.example.app", "android.permission.INTERNET"),
            observed("obs-1", "com.example.app", None),
        ];
        let result = bind_authority(&events);
        assert!(result.authorized.is_empty());
        assert!(
            result.unauthorized_observed.is_empty(),
            "an unmapped action must not count as unauthorized"
        );
        assert_eq!(result.unused_grants, vec!["grant-1".to_string()]);
    }

    #[test]
    fn grant_never_exercised_is_unused() {
        let events = vec![grant(
            "grant-1",
            "com.example.app",
            "android.permission.CAMERA",
        )];
        let result = bind_authority(&events);
        assert_eq!(result.unused_grants, vec!["grant-1".to_string()]);
    }

    #[test]
    fn one_grant_authorizes_multiple_observed_actions() {
        let events = vec![
            grant("grant-1", "com.example.app", "android.permission.INTERNET"),
            observed(
                "obs-1",
                "com.example.app",
                Some("android.permission.INTERNET"),
            ),
            observed(
                "obs-2",
                "com.example.app",
                Some("android.permission.INTERNET"),
            ),
        ];
        let result = bind_authority(&events);
        assert_eq!(result.authorized.len(), 2);
        assert!(result.unused_grants.is_empty());
    }

    #[test]
    fn empty_input_produces_empty_result() {
        let result = bind_authority(&[]);
        assert_eq!(result, AuthorityBindingResult::default());
    }

    #[test]
    fn non_authority_events_are_ignored() {
        let mut attrs = BTreeMap::new();
        attrs.insert("method".to_string(), "GET".to_string());
        attrs.insert("url".to_string(), "/".to_string());
        let http_event = TypedEvent {
            id: "http-1".to_string(),
            sensor_id: "mitm-local".to_string(),
            kind: EventKind::HttpRequest,
            observed_at_ms: 0,
            subjects: vec![],
            description: "GET /".to_string(),
            score: 0.0,
            attributes: attrs,
            evidence_refs: vec![],
        };
        let result = bind_authority(&[http_event]);
        assert_eq!(result, AuthorityBindingResult::default());
    }
}
