/*
 * Copyright 2026 Julien Bombled
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Named-profile CRUD operations for [`RouteWardController`].

use super::{RouteWardController, COMPONENT_ENGINE};
use crate::config::security::verify_profile_path_security;
use crate::config::{is_valid_profile_slug, slugify_profile_id, ProfileConfig, ProfileSummary};
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_CONFIG_LOAD};
use crate::telemetry::LogLevel;

impl RouteWardController {
    pub fn list_named_profiles(&self) -> RouteWardResult<Vec<ProfileSummary>> {
        let dir = self.ensure_profiles_dir()?;
        let active_prof = self.profile.read().clone();
        let active_id = if is_valid_profile_slug(&active_prof.profile_id) {
            active_prof.profile_id.clone()
        } else {
            slugify_profile_id(&active_prof.name)
        };

        let active_named_path = dir.join(format!("{active_id}.json"));
        Self::reject_if_symlink(&active_named_path)?;
        if !active_named_path.exists() {
            let mut normalized = active_prof.clone();
            normalized.profile_id = active_id.clone();
            normalized.save_to_path(&active_named_path)?;
            Self::apply_and_verify_secure_file_if_elevated(&active_named_path)?;
        }

        let elevated = Self::detect_elevated_privileges();
        let mut summaries = Vec::new();
        let entries = std::fs::read_dir(&dir).map_err(|err| RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_LOAD,
            detail: format!("Failed to read profiles directory {}: {err}", dir.display()),
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if !is_valid_profile_slug(stem) {
                continue;
            }
            if Self::reject_if_symlink(&path).is_err() {
                continue;
            }
            if elevated {
                if let Err(err) = verify_profile_path_security(&path) {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_ENGINE,
                        format!("Skipping insecure named profile {}: {err}", path.display()),
                    );
                    continue;
                }
            }
            if let Ok(loaded) = ProfileConfig::load_from_path(&path) {
                summaries.push(ProfileSummary {
                    profile_id: stem.to_string(),
                    name: loaded.name,
                    proxy_count: loaded.proxies.len(),
                    rule_count: loaded.rules.len(),
                    active: stem == active_id,
                });
            }
        }

        summaries.sort_by(|a, b| {
            b.active.cmp(&a.active).then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
        });
        Ok(summaries)
    }

    pub fn save_named_profile(
        &self,
        profile_id: Option<&str>,
        name: Option<&str>,
    ) -> RouteWardResult<Vec<ProfileSummary>> {
        let dir = self.ensure_profiles_dir()?;
        let mut updated = self.profile.read().clone();
        if let Some(new_name) = name.map(str::trim).filter(|s| !s.is_empty()) {
            updated.name = new_name.to_string();
        }
        let target_slug = match profile_id.map(str::trim).filter(|s| !s.is_empty()) {
            Some(id) if is_valid_profile_slug(id) => id.to_string(),
            Some(_) => {
                return Err(RouteWardError::ConfigError {
                    key: ERR_KEY_CONFIG_LOAD,
                    detail: "Invalid profile identifier (expected [a-z0-9_-]{1,48})".to_string(),
                });
            }
            None => slugify_profile_id(&updated.name),
        };
        updated.profile_id = target_slug.clone();
        *self.profile.write() = updated.clone();

        let named_path = dir.join(format!("{target_slug}.json"));
        Self::reject_if_symlink(&named_path)?;
        updated.save_to_path(&named_path)?;
        Self::apply_and_verify_secure_file_if_elevated(&named_path)?;
        self.save_profile_default()?;
        self.list_named_profiles()
    }

    pub fn switch_named_profile(&self, profile_id: &str) -> RouteWardResult<ProfileConfig> {
        let slug = profile_id.trim();
        if !is_valid_profile_slug(slug) {
            return Err(RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: format!("Invalid profile identifier \"{profile_id}\""),
            });
        }
        let dir = self.ensure_profiles_dir()?;
        let named_path = dir.join(format!("{slug}.json"));
        Self::reject_if_symlink(&named_path)?;
        if !named_path.exists() {
            return Err(RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: format!("Profile \"{slug}\" not found"),
            });
        }
        if Self::detect_elevated_privileges() {
            verify_profile_path_security(&named_path)?;
        }
        let mut loaded = ProfileConfig::load_from_path(&named_path)?;
        loaded.profile_id = slug.to_string();
        self.replace_profile(loaded)?;
        self.save_profile_default()?;
        Ok(self.profile.read().redacted_for_ipc())
    }

    pub fn delete_named_profile(&self, profile_id: &str) -> RouteWardResult<Vec<ProfileSummary>> {
        let slug = profile_id.trim();
        if !is_valid_profile_slug(slug) {
            return Err(RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: format!("Invalid profile identifier \"{profile_id}\""),
            });
        }
        let active_id = self.profile.read().profile_id.clone();
        if slug == "default" || slug == active_id {
            return Err(RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: "Cannot delete the default or currently active profile".to_string(),
            });
        }
        let dir = self.ensure_profiles_dir()?;
        let named_path = dir.join(format!("{slug}.json"));
        Self::reject_if_symlink(&named_path)?;
        if named_path.exists() {
            std::fs::remove_file(&named_path).map_err(|err| RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: format!(
                    "Failed to delete profile \"{}\": {err}",
                    named_path.display()
                ),
            })?;
        }
        self.list_named_profiles()
    }
}
