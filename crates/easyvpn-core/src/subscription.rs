use crate::store::Store;
use crate::Profile;
use anyhow::{anyhow, Context, Result};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn fetch(url: &str) -> Result<Vec<Profile>> {
    let response = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(20))
        .build()
        .get(url)
        .set(
            "User-Agent",
            concat!("EasyVpn/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .context("fetching subscription")?;
    let text = response
        .into_string()
        .context("reading subscription response")?;
    Ok(crate::import::import_text(&text, None))
}

pub fn update(store: &mut Store, sub_id: &str) -> Result<usize> {
    let url = store
        .subscriptions
        .iter()
        .find(|sub| sub.id == sub_id)
        .ok_or_else(|| anyhow!("subscription not found: {sub_id}"))?
        .url
        .clone();

    // Do all fallible work before changing the store.
    let profiles = fetch(&url)?;
    let updated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let selected_identity = store
        .selected_profile()
        .filter(|p| p.subscription_id.as_deref() == Some(sub_id))
        .map(|p| (p.name.clone(), p.address.clone()));

    store
        .profiles
        .retain(|p| p.subscription_id.as_deref() != Some(sub_id));
    if selected_identity.is_some() {
        store.selected = None;
    }

    let count = profiles.len();
    for mut profile in profiles {
        profile.id.clear();
        profile.subscription_id = Some(sub_id.to_owned());
        let matches_selected = selected_identity
            .as_ref()
            .map(|(name, address)| profile.name == *name && profile.address == *address)
            .unwrap_or(false);
        let id = store.add_profile(profile);
        if matches_selected && store.selected.is_none() {
            store.selected = Some(id);
        }
    }

    if let Some(sub) = store.subscriptions.iter_mut().find(|sub| sub.id == sub_id) {
        sub.updated_at = updated_at;
    }
    Ok(count)
}

pub fn update_all(store: &mut Store) -> Vec<(String, Result<usize>)> {
    let ids: Vec<String> = store
        .subscriptions
        .iter()
        .map(|sub| sub.id.clone())
        .collect();
    ids.into_iter()
        .map(|id| {
            let result = update(store, &id);
            (id, result)
        })
        .collect()
}
