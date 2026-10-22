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

use parking_lot::RwLock;
use serde_json::Value;
use std::sync::Arc;

const EN_LOCALE_RAW: &str = include_str!("../../../../locales/en.json");
const FR_LOCALE_RAW: &str = include_str!("../../../../locales/fr.json");
const DEFAULT_LOCALE_CODE: &str = "fr";
const FALLBACK_LOCALE_CODE: &str = "en";
const KEY_PATH_SEPARATOR: char = '.';

#[derive(Clone)]
pub struct I18nRegistry {
    active_locale: Arc<RwLock<String>>,
    en_tree: Arc<Value>,
    fr_tree: Arc<Value>,
}

impl Default for I18nRegistry {
    fn default() -> Self {
        Self::new(DEFAULT_LOCALE_CODE)
    }
}

impl I18nRegistry {
    pub fn new(initial_locale: &str) -> Self {
        let en_tree: Value = serde_json::from_str(EN_LOCALE_RAW).unwrap_or(Value::Null);
        let fr_tree: Value = serde_json::from_str(FR_LOCALE_RAW).unwrap_or(Value::Null);
        Self {
            active_locale: Arc::new(RwLock::new(initial_locale.to_lowercase())),
            en_tree: Arc::new(en_tree),
            fr_tree: Arc::new(fr_tree),
        }
    }

    pub fn set_locale(&self, locale: &str) {
        let mut guard = self.active_locale.write();
        *guard = locale.to_lowercase();
    }

    pub fn get_locale(&self) -> String {
        self.active_locale.read().clone()
    }

    pub fn t(&self, key_path: &str) -> String {
        let locale = self.active_locale.read().clone();
        let primary_tree = if locale.starts_with(DEFAULT_LOCALE_CODE) {
            &self.fr_tree
        } else {
            &self.en_tree
        };

        if let Some(resolved) = Self::lookup_path(primary_tree, key_path) {
            return resolved;
        }
        if locale != FALLBACK_LOCALE_CODE {
            if let Some(fallback) = Self::lookup_path(&self.en_tree, key_path) {
                return fallback;
            }
        }
        key_path.to_string()
    }

    fn lookup_path(root: &Value, key_path: &str) -> Option<String> {
        let mut cursor = root;
        for segment in key_path.split(KEY_PATH_SEPARATOR) {
            cursor = cursor.get(segment)?;
        }
        cursor.as_str().map(ToOwned::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_french_and_english_keys() {
        let i18n = I18nRegistry::new("fr");
        assert_eq!(i18n.t("app.header.engine.running"), "Intercepteur Actif");
        i18n.set_locale("en");
        assert_eq!(i18n.t("app.header.engine.running"), "Interceptor Active");
    }
}
