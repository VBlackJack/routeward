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

//! Download destination policy for the embedded WebView.
//!
//! Exports are produced by the UI as `blob:` downloads. Letting the browser engine
//! handle them makes WebView2 raise its "download multiple files" prompt on the second
//! export, so the host picks the destination itself: the user's Downloads folder, with
//! a numeric suffix when the file name is already taken.

use std::path::{Path, PathBuf};

const DOWNLOADS_DIR_NAME: &str = "Downloads";
const FALLBACK_FILE_NAME: &str = "download";
/// Upper bound of numeric suffixes tried before giving up on a unique name.
const MAX_UNIQUE_SUFFIX: u32 = 999;

#[cfg(target_os = "windows")]
const HOME_ENV_VAR: &str = "USERPROFILE";
#[cfg(not(target_os = "windows"))]
const HOME_ENV_VAR: &str = "HOME";

/// Returns the per-user Downloads directory, or `None` when the home directory is unknown.
pub fn default_downloads_dir() -> Option<PathBuf> {
    let home = std::env::var_os(HOME_ENV_VAR)?;
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home).join(DOWNLOADS_DIR_NAME))
}

/// Builds the destination of a download inside `dir`, keeping only the final file name
/// component of `suggested` and appending ` (n)` before the extension until `exists`
/// reports the candidate as free.
pub fn resolve_download_path(
    dir: &Path,
    suggested: &Path,
    exists: impl Fn(&Path) -> bool,
) -> PathBuf {
    let file_name = suggested
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or(FALLBACK_FILE_NAME);
    let candidate = dir.join(file_name);
    if !exists(&candidate) {
        return candidate;
    }
    let as_path = Path::new(file_name);
    let stem = as_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(file_name);
    let extension = as_path.extension().and_then(|e| e.to_str());
    for n in 1..=MAX_UNIQUE_SUFFIX {
        let name = match extension {
            Some(ext) => format!("{stem} ({n}).{ext}"),
            None => format!("{stem} ({n})"),
        };
        let numbered = dir.join(name);
        if !exists(&numbered) {
            return numbered;
        }
    }
    candidate
}

/// Rewrites `path` so the download lands in the Downloads folder. Returns `false`
/// (cancel the download) only when the destination folder cannot be created.
pub fn redirect_download(path: &mut PathBuf) -> bool {
    let Some(dir) = default_downloads_dir() else {
        // No home directory known: keep the engine's own suggestion.
        return true;
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    *path = resolve_download_path(&dir, path, |p| p.exists());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_name_is_kept_and_directories_are_stripped() {
        let dir = Path::new("dl");
        let got = resolve_download_path(dir, Path::new("x/y/a.csv"), |_| false);
        assert_eq!(got, dir.join("a.csv"));
    }

    #[test]
    fn taken_names_get_a_numeric_suffix_before_the_extension() {
        let dir = Path::new("dl");
        let taken = [dir.join("a.json"), dir.join("a (1).json")];
        let got = resolve_download_path(dir, Path::new("a.json"), |p| taken.iter().any(|t| t == p));
        assert_eq!(got, dir.join("a (2).json"));
    }

    #[test]
    fn empty_suggestion_uses_fallback_name() {
        let dir = Path::new("dl");
        let got = resolve_download_path(dir, Path::new(""), |_| false);
        assert_eq!(got, dir.join(FALLBACK_FILE_NAME));
    }
}
