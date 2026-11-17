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

//! Removal of the machine-wide RouteWard data directory (`%ProgramData%\RouteWard`), used by
//! `routeward purge-data` when the product is uninstalled.

use super::user_state::DATA_DIR_NAME;
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_SYSTEM_PURGE_FAILED};
use std::fs::Metadata;
use std::io;
use std::path::Path;

/// True for symbolic links and, on Windows, for every reparse point (junctions, mount points).
/// Such entries are removed as links and never entered.
pub(crate) fn is_link_like(meta: &Metadata) -> bool {
    meta.file_type().is_symlink() || is_reparse_point(meta)
}

/// True when a Windows entry carries `FILE_ATTRIBUTE_REPARSE_POINT` (junction, mount point).
#[cfg(windows)]
fn is_reparse_point(meta: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Reparse points only exist on Windows; symbolic links are covered by `is_link_like`.
#[cfg(not(windows))]
fn is_reparse_point(_meta: &Metadata) -> bool {
    false
}

/// Removes the link object itself, never its target. A directory link (symlink or junction on
/// Windows) needs `remove_dir`, which refuses to touch a real, non-empty directory.
fn remove_link(path: &Path) -> io::Result<()> {
    std::fs::remove_file(path).or_else(|_| std::fs::remove_dir(path))
}

/// Deletes `path` recursively without ever following a link out of the tree.
///
/// Every entry is inspected with `symlink_metadata`; links are removed as links. Removal
/// continues past a failing entry and the first error is returned at the end, so one locked file
/// does not leave the rest of the data behind. A missing path is success (idempotent).
pub fn remove_tree_no_follow(path: &Path) -> io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if is_link_like(&meta) {
        return remove_link(path);
    }
    if !meta.is_dir() {
        return std::fs::remove_file(path);
    }
    let mut first_error: Option<io::Error> = None;
    for entry in std::fs::read_dir(path)? {
        let result = entry.and_then(|entry| remove_tree_no_follow(&entry.path()));
        if let Err(err) = result {
            first_error.get_or_insert(err);
        }
    }
    if let Some(err) = first_error {
        return Err(err);
    }
    std::fs::remove_dir(path)
}

/// Deletes the RouteWard data directory `dir`.
///
/// Refuses any path whose last component is not `RouteWard`, so a wrong resolution can never
/// turn into the deletion of a parent such as `%ProgramData%` itself. Before anything is
/// removed, the directory itself must pass `verify_profile_path_security` (owned by
/// SYSTEM/Administrators or root, no entry granting access to another principal): a directory
/// a standard user could write to may hold links or files planted to steer the deletion.
pub fn purge_data_dir(dir: &Path) -> RouteWardResult<()> {
    purge_data_dir_with(dir, crate::config::security::verify_profile_path_security)
}

/// [`purge_data_dir`] with the directory security check injected, so the refusal path and the
/// removal logic are testable without an administrator-owned directory.
fn purge_data_dir_with(
    dir: &Path,
    verify_security: impl Fn(&Path) -> RouteWardResult<()>,
) -> RouteWardResult<()> {
    let name_ok = dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(DATA_DIR_NAME));
    if !name_ok {
        return Err(RouteWardError::SystemError {
            key: ERR_KEY_SYSTEM_PURGE_FAILED,
            detail: format!("refusing to remove unexpected directory {}", dir.display()),
        });
    }
    match std::fs::symlink_metadata(dir) {
        // Already gone: nothing to verify, nothing to remove.
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        // A link is removed as a link and never entered, so its target's security is moot.
        Ok(meta) if is_link_like(&meta) => {}
        Ok(_) => verify_security(dir).map_err(|err| RouteWardError::SystemError {
            key: ERR_KEY_SYSTEM_PURGE_FAILED,
            detail: format!(
                "refusing to remove {} because its security is not trusted: {err}",
                dir.display()
            ),
        })?,
        Err(err) => {
            return Err(RouteWardError::SystemError {
                key: ERR_KEY_SYSTEM_PURGE_FAILED,
                detail: format!("cannot inspect {}: {err}", dir.display()),
            })
        }
    }
    remove_tree_no_follow(dir).map_err(|err| RouteWardError::SystemError {
        key: ERR_KEY_SYSTEM_PURGE_FAILED,
        detail: format!("cannot remove {}: {err}", dir.display()),
    })
}

/// Resolves `%ProgramData%\RouteWard` through the known-folder API (Windows only).
#[cfg(windows)]
pub fn program_data_dir() -> RouteWardResult<std::path::PathBuf> {
    Ok(crate::config::security::resolve_windows_program_data_dir()?.join(DATA_DIR_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifier that accepts any directory: temp directories are not administrator-owned.
    fn trust_everything(_dir: &Path) -> RouteWardResult<()> {
        Ok(())
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("routeward-purge-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn purge_removes_a_nested_tree_and_is_idempotent() {
        let root = scratch("tree");
        let data = root.join(DATA_DIR_NAME);
        std::fs::create_dir_all(data.join("logs").join("old")).unwrap();
        std::fs::write(data.join("active_profile.json"), "{}").unwrap();
        std::fs::write(data.join("logs").join("old").join("a.log"), "x").unwrap();

        purge_data_dir_with(&data, trust_everything).unwrap();
        assert!(!data.exists());
        purge_data_dir_with(&data, trust_everything).unwrap();
        assert!(root.exists(), "the parent must never be removed");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn purge_refuses_a_directory_that_is_not_named_routeward() {
        let root = scratch("refuse");
        std::fs::write(root.join("keep.txt"), "x").unwrap();
        let err = purge_data_dir_with(&root, trust_everything).unwrap_err();
        assert_eq!(err.i18n_key(), ERR_KEY_SYSTEM_PURGE_FAILED);
        assert!(root.join("keep.txt").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Creates a directory link `link` -> `target` (junction on Windows, symlink elsewhere).
    fn make_dir_link(link: &Path, target: &Path) -> bool {
        #[cfg(windows)]
        {
            std::process::Command::new(super::super::windows_system_tool_path("cmd.exe"))
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false)
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
    }

    #[test]
    fn purge_removes_a_link_but_never_its_target() {
        let root = scratch("link");
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("precious.txt"), "keep").unwrap();

        let data = root.join(DATA_DIR_NAME);
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("a.txt"), "x").unwrap();
        if !make_dir_link(&data.join("escape"), &outside) {
            eprintln!("directory links unavailable here, skipping");
            let _ = std::fs::remove_dir_all(&root);
            return;
        }

        purge_data_dir_with(&data, trust_everything).unwrap();
        assert!(!data.exists());
        assert!(
            outside.join("precious.txt").exists(),
            "link target was followed"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn purge_of_a_root_that_is_itself_a_link_removes_only_the_link() {
        let root = scratch("rootlink");
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("precious.txt"), "keep").unwrap();
        let data = root.join(DATA_DIR_NAME);
        if !make_dir_link(&data, &outside) {
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        purge_data_dir_with(&data, trust_everything).unwrap();
        assert!(!data.exists());
        assert!(outside.join("precious.txt").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn purge_refuses_an_untrusted_directory_and_removes_nothing() {
        let root = scratch("untrusted");
        let data = root.join(DATA_DIR_NAME);
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("keep.txt"), "x").unwrap();

        let err = purge_data_dir_with(&data, |_| {
            Err(RouteWardError::SystemError {
                key: ERR_KEY_SYSTEM_PURGE_FAILED,
                detail: "writable by a standard user".into(),
            })
        })
        .unwrap_err();
        assert_eq!(err.i18n_key(), ERR_KEY_SYSTEM_PURGE_FAILED);
        assert!(data.join("keep.txt").exists(), "nothing may be removed");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn purge_verifies_the_directory_before_removing_it_and_skips_a_missing_one() {
        use std::cell::Cell;
        let root = scratch("verified");
        let data = root.join(DATA_DIR_NAME);
        std::fs::create_dir_all(&data).unwrap();

        let calls = Cell::new(0);
        let counting = |dir: &Path| {
            assert!(dir.exists(), "verification must run before the removal");
            calls.set(calls.get() + 1);
            Ok(())
        };
        purge_data_dir_with(&data, counting).unwrap();
        assert_eq!(calls.get(), 1);
        assert!(!data.exists());

        purge_data_dir_with(&data, counting).unwrap();
        assert_eq!(calls.get(), 1, "a missing directory is not verified");
        let _ = std::fs::remove_dir_all(&root);
    }
}
