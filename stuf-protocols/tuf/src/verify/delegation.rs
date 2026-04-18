use crate::{
    error::{Error, Result},
    schema::{
        role::RoleKeys,
        targets::{DelegatedRole, Targets},
    },
    sign::traits::Verifier,
    verify::{
        expiry::check_expiry,
        root::count_valid_signatures,
        state::{Clock, Unverified, Verified},
    },
};
use std::collections::{HashMap, HashSet};

/// Maximum delegation depth to prevent infinite loops.
const MAX_DELEGATION_DEPTH: usize = 8;

/// Find and verify the delegated targets role responsible for a
/// given target path, starting from the top-level targets.
///
/// Walks the delegation graph in order, respecting terminating flags
/// and path matching. Returns the verified targets role that owns
/// the requested path, or an error if none is found.
pub fn find_target<'a, F>(
    target_name: &str,
    top_level_targets: &'a Verified<Targets>,
    fetch_metadata: &mut F,
    verifier: &dyn Verifier,
    clock: &dyn Clock,
) -> Result<Verified<Targets>>
where
    F: FnMut(&str) -> Vec<u8>,
{
    // If top-level targets has this target directly, no delegation needed
    if top_level_targets.get().get_target(target_name).is_some() {
        // Clone to return — caller already has top-level, this signals
        // "found at top level" without a separate return type
        return Ok(top_level_targets.clone());
    }

    let mut visited: HashSet<String> = HashSet::new();
    search_delegations(
        target_name,
        top_level_targets,
        fetch_metadata,
        verifier,
        clock,
        &mut visited,
        0,
    )
}

fn search_delegations<F>(
    target_name: &str,
    current: &Verified<Targets>,
    fetch_metadata: &mut F,
    verifier: &dyn Verifier,
    clock: &dyn Clock,
    visited: &mut HashSet<String>,
    depth: usize,
) -> Result<Verified<Targets>>
where
    F: FnMut(&str) -> Vec<u8>,
{
    if depth > MAX_DELEGATION_DEPTH {
        return Err(Error::DelegationDepthExceeded);
    }

    for role in current.get().delegated_roles() {
        if visited.contains(&role.name) {
            return Err(Error::DelegationCycle(role.name.clone()));
        }

        if !path_matches(target_name, role) {
            if role.terminating {
                // Terminating role that doesn't match — stop searching
                return Err(Error::TargetNotFound(target_name.to_string()));
            }
            continue;
        }

        // Fetch and verify the delegated role's metadata
        let filename = format!("{}.json", role.name);
        let bytes = fetch_metadata(&filename);

        let delegations = current
            .get()
            .delegations
            .as_ref()
            .ok_or_else(|| Error::TargetNotFound(target_name.to_string()))?;

        let role_keys = RoleKeys {
            keyids: role.keyids.clone(),
            threshold: role.threshold,
        };

        let unverified: Unverified<crate::schema::signed::Signed<Targets>> =
            Unverified::from_bytes(&bytes)?;

        let canonical = unverified.canonical_bytes()?;
        let valid = count_valid_signatures(
            unverified.signatures(),
            &role_keys,
            &delegations.keys,
            &canonical,
            verifier,
        );

        if !role_keys.threshold_met(valid) {
            if role.terminating {
                return Err(Error::ThresholdNotMet {
                    threshold: role_keys.threshold,
                    valid,
                });
            }
            continue;
        }

        let verified = unverified.into_verified();
        check_expiry(&verified, clock)?;

        // Found target in this delegated role
        if verified.get().get_target(target_name).is_some() {
            return Ok(verified);
        }

        // Recurse into this role's own delegations
        visited.insert(role.name.clone());
        match search_delegations(
            target_name,
            &verified,
            fetch_metadata,
            verifier,
            clock,
            visited,
            depth + 1,
        ) {
            Ok(found) => return Ok(found),
            Err(Error::TargetNotFound(_)) => {
                visited.remove(&role.name);
                if role.terminating {
                    return Err(Error::TargetNotFound(target_name.to_string()));
                }
                // Not terminating — continue to next delegated role
            }
            Err(e) => return Err(e),
        }
    }

    Err(Error::TargetNotFound(target_name.to_string()))
}

/// Check whether a target path matches a delegated role's path set.
fn path_matches(target: &str, role: &DelegatedRole) -> bool {
    use crate::schema::targets::PathSet;
    match &role.paths {
        PathSet::Any => true,
        PathSet::Paths { paths } => paths.iter().any(|pattern| {
            // Simple glob: trailing * matches any suffix
            if let Some(prefix) = pattern.strip_suffix('*') {
                target.starts_with(prefix)
            } else {
                target == pattern
            }
        }),
    }
}

