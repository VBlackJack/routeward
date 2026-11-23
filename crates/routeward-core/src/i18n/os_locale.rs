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

//! Operating-system language detection, shared by the CLI and the desktop app.

const ENGLISH_LOCALE: &str = "en";
const FRENCH_LOCALE: &str = "fr";
const FRENCH_LOCALE_PREFIX: &str = "fr";
const ENGLISH_LOCALE_PREFIX: &str = "en";
/// Characters that end the language part of a POSIX locale (`fr_FR.UTF-8@euro`).
const POSIX_MODIFIER_SEPARATORS: [char; 2] = ['.', '@'];
/// POSIX locale names that mean "no localisation": messages stay in English.
const POSIX_NEUTRAL_LOCALES: [&str; 2] = ["c", "posix"];
/// Separator between the entries of the GNU `LANGUAGE` priority list.
const LANGUAGE_LIST_SEPARATOR: char = ':';
#[cfg(not(target_os = "windows"))]
const ENV_LC_ALL: &str = "LC_ALL";
#[cfg(not(target_os = "windows"))]
const ENV_LC_MESSAGES: &str = "LC_MESSAGES";
#[cfg(not(target_os = "windows"))]
const ENV_LANG: &str = "LANG";
#[cfg(not(target_os = "windows"))]
const ENV_LANGUAGE: &str = "LANGUAGE";
#[cfg(target_os = "windows")]
const OS_LOCALE_NAME_MAX_LEN: usize = 85;

/// Maps an operating-system locale name (`fr-FR`, `en-US`, `fr_CA.UTF-8`) to a supported locale:
/// any French variant gives French, everything else English.
pub fn locale_from_os_name(name: &str) -> &'static str {
    if name
        .trim()
        .to_ascii_lowercase()
        .starts_with(FRENCH_LOCALE_PREFIX)
    {
        FRENCH_LOCALE
    } else {
        ENGLISH_LOCALE
    }
}

/// Maps an OS locale name to a supported locale, or `None` when it is not one of them.
fn supported_locale_from_os_name(name: &str) -> Option<&'static str> {
    let lower = name.trim().to_ascii_lowercase();
    if lower.starts_with(FRENCH_LOCALE_PREFIX) {
        Some(FRENCH_LOCALE)
    } else if lower.starts_with(ENGLISH_LOCALE_PREFIX) {
        Some(ENGLISH_LOCALE)
    } else {
        None
    }
}

/// Resolves the POSIX locale from the four environment variables, as plain values so the logic
/// is testable without touching the process environment. Order: `LC_ALL`, `LC_MESSAGES`, `LANG`
/// (empty values are skipped). `C` and `POSIX` mean English. Otherwise the first entry of
/// `LANGUAGE`, when set, wins over the effective locale.
pub fn locale_from_posix_env(
    lc_all: Option<&str>,
    lc_messages: Option<&str>,
    lang: Option<&str>,
    language: Option<&str>,
) -> &'static str {
    let effective = [lc_all, lc_messages, lang]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty());
    let Some(effective) = effective else {
        return ENGLISH_LOCALE;
    };
    // Compare the language part only: `C.UTF-8` and `POSIX@x` are neutral too.
    let base = effective
        .split(POSIX_MODIFIER_SEPARATORS)
        .next()
        .unwrap_or(effective);
    let neutral = POSIX_NEUTRAL_LOCALES
        .iter()
        .any(|name| base.eq_ignore_ascii_case(name));
    if neutral {
        return ENGLISH_LOCALE;
    }
    // First `LANGUAGE` entry that maps to a supported locale (`de:fr` gives French).
    let from_language = language.and_then(|list| {
        list.split(LANGUAGE_LIST_SEPARATOR)
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .find_map(supported_locale_from_os_name)
    });
    from_language.unwrap_or_else(|| locale_from_os_name(effective))
}

/// The locale of the operating system user, as a supported locale (`"en"` or `"fr"`).
pub fn os_default_locale() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
        let mut buffer = [0u16; OS_LOCALE_NAME_MAX_LEN];
        // SAFETY: the buffer is valid for `OS_LOCALE_NAME_MAX_LEN` UTF-16 units, which is the
        // size passed; the function writes a NUL-terminated name and returns its length.
        let written =
            unsafe { GetUserDefaultLocaleName(buffer.as_mut_ptr(), OS_LOCALE_NAME_MAX_LEN as i32) };
        if written <= 0 {
            return ENGLISH_LOCALE;
        }
        let len = buffer.iter().position(|&unit| unit == 0).unwrap_or(0);
        locale_from_os_name(&String::from_utf16_lossy(&buffer[..len]))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let read = |name: &str| std::env::var(name).ok();
        locale_from_posix_env(
            read(ENV_LC_ALL).as_deref(),
            read(ENV_LC_MESSAGES).as_deref(),
            read(ENV_LANG).as_deref(),
            read(ENV_LANGUAGE).as_deref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_names_map_to_french_or_english() {
        assert_eq!(locale_from_os_name("fr-FR"), "fr");
        assert_eq!(locale_from_os_name("fr_CA.UTF-8"), "fr");
        assert_eq!(locale_from_os_name("FR"), "fr");
        assert_eq!(locale_from_os_name("en-US"), "en");
        assert_eq!(locale_from_os_name("de-DE"), "en");
        assert_eq!(locale_from_os_name(""), "en");
    }

    #[test]
    fn posix_order_is_lc_all_then_lc_messages_then_lang() {
        let fr = Some("fr_FR.UTF-8");
        let en = Some("en_US.UTF-8");
        assert_eq!(locale_from_posix_env(en, fr, fr, None), "en");
        assert_eq!(locale_from_posix_env(None, fr, en, None), "fr");
        assert_eq!(locale_from_posix_env(None, None, fr, None), "fr");
        assert_eq!(locale_from_posix_env(None, None, None, None), "en");
    }

    #[test]
    fn posix_empty_values_are_skipped() {
        let fr = Some("fr_FR.UTF-8");
        assert_eq!(locale_from_posix_env(Some(""), Some(""), fr, None), "fr");
        assert_eq!(locale_from_posix_env(Some("  "), None, fr, None), "fr");
    }

    #[test]
    fn posix_c_and_posix_mean_english_and_ignore_language() {
        let fr = Some("fr_FR.UTF-8");
        assert_eq!(locale_from_posix_env(Some("C"), None, fr, fr), "en");
        assert_eq!(locale_from_posix_env(None, None, Some("POSIX"), fr), "en");
        assert_eq!(
            locale_from_posix_env(None, None, Some("C.UTF-8"), None),
            "en"
        );
    }

    #[test]
    fn posix_language_first_entry_wins_over_the_effective_locale() {
        let en = Some("en_US.UTF-8");
        assert_eq!(locale_from_posix_env(None, None, en, Some("fr:en")), "fr");
        assert_eq!(
            locale_from_posix_env(None, None, Some("fr_FR.UTF-8"), Some("en:fr")),
            "en"
        );
        assert_eq!(locale_from_posix_env(None, None, en, Some("")), "en");
    }

    #[test]
    fn posix_c_utf8_is_neutral_and_ignores_language() {
        let fr = Some("fr");
        assert_eq!(locale_from_posix_env(None, None, Some("C.UTF-8"), fr), "en");
        assert_eq!(locale_from_posix_env(Some("POSIX@x"), None, None, fr), "en");
        // A locale that merely starts with `c` is not neutral.
        assert_eq!(
            locale_from_posix_env(None, None, Some("ca_ES.UTF-8"), fr),
            "fr"
        );
    }

    #[test]
    fn posix_language_picks_the_first_supported_entry() {
        let en = Some("en_US.UTF-8");
        assert_eq!(locale_from_posix_env(None, None, en, Some("de:fr")), "fr");
        assert_eq!(
            locale_from_posix_env(None, None, en, Some("de:en:fr")),
            "en"
        );
        assert_eq!(locale_from_posix_env(None, None, en, Some(":de:fr")), "fr");
        assert_eq!(
            locale_from_posix_env(None, None, Some("fr_FR.UTF-8"), Some("de:es")),
            "fr"
        );
    }
}
