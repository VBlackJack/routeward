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

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SKIPPED_DIRS: &[&str] = &[
    ".git",
    ".claude",
    "target",
    "node_modules",
    "dist",
    "local",
    "logs",
    "third_party",
];

const TEXT_EXTENSIONS: &[&str] = &[
    "rs", "ts", "tsx", "js", "jsx", "css", "html", "md", "json", "toml", "yml", "yaml", "ps1",
    "sh", "py", "bat", "wxs", "svg", "rc", "template", "service",
];

/// Extensionless packaging scripts that are scanned as text (maintainer scripts of the .deb).
const TEXT_FILE_NAMES: &[&str] = &["Dockerfile", "postinst", "prerm", ".env.example"];

const SOURCE_HEADER_EXTENSIONS: &[&str] = &[
    "rs", "ts", "tsx", "css", "ps1", "sh", "py", "js", "bat", "wxs", "toml", "yml", "html",
];

/// Number of leading lines in which the license header must appear.
const HEADER_SCAN_LINES: usize = 20;

/// Locale keys that are built at runtime (for example `t(`app.nav.${id}`)`) and therefore
/// never appear as complete literals in the sources. Each prefix must stay justified here.
const DYNAMIC_LOCALE_KEY_PREFIXES: &[&str] = &[
    // App.tsx: `app.nav.${id}.tab`
    "app.nav.",
    // ConnectionsView.tsx: `connections.table.status.${conn.status}`
    "connections.table.status.",
    // ConnectionsView.tsx: `connections.toolbar.status_filter.${st}`
    "connections.toolbar.status_filter.",
    // GlossaryModal.tsx: `glossary.items.${key}.term|simple|expert`
    "glossary.items.",
    // LogsView.tsx: `logs.toolbar.filter_${level}`
    "logs.toolbar.filter_",
    // ProxiesView.tsx: `proxies.strategy.mode.${strategy}`
    "proxies.strategy.mode.",
    // RulesView.tsx, App.tsx, wizard: `${preset.i18nKey}.name|desc` (keys come from configs)
    "rules.presets.",
    "rules.visual_apps.",
    // RulesView.tsx: `rules.table.action.${rule.action.type}`
    "rules.table.action.",
    // ThemeForgeModal.tsx: `themeforge.accents.${accent}` and `themeforge.families.${family}`
    "themeforge.accents.",
    "themeforge.families.",
];

/// Directories whose sources may reference locale keys (UI, desktop bridge, Rust crates, and the
/// embedded configs that carry `i18nKey` values).
const LOCALE_REFERENCE_DIRS: &[&str] = &["ui/src", "apps/desktop/src", "crates", "configs"];

const LOCALE_REFERENCE_EXTENSIONS: &[&str] = &["rs", "ts", "tsx", "js", "jsx", "json"];

const RELEASE_NOTES_DIRS: &[&str] = &["docs/release-notes", "docs/fr/release-notes"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Walks the working tree. Symbolic links are never followed or returned.
fn collect_files_recursive(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        panic!("Failed to read directory {:?}", dir);
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if SKIPPED_DIRS.iter().any(|skip| *skip == name) {
                continue;
            }
            collect_files_recursive(root, &path, out);
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .expect("relative path")
                .to_path_buf();
            out.push(rel);
        }
    }
}

/// Lists tracked files plus untracked files that are not ignored, so untracked directories
/// such as `.claude/worktrees` never enter the scan. Returns `None` when git is unavailable.
fn collect_files_from_git(root: &Path) -> Option<Vec<PathBuf>> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut files = Vec::new();
    for raw in output.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let rel = PathBuf::from(String::from_utf8_lossy(raw).into_owned());
        let in_skipped_dir = rel.components().any(|c| {
            c.as_os_str()
                .to_str()
                .is_some_and(|n| SKIPPED_DIRS.contains(&n))
        });
        if in_skipped_dir {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(root.join(&rel)) else {
            // Listed by git but deleted in the working tree.
            continue;
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            continue;
        }
        files.push(rel);
    }
    Some(files)
}

/// Enumerates repository files through `git ls-files`, falling back to a directory walk.
fn collect_repo_files(root: &Path) -> Vec<PathBuf> {
    if let Some(files) = collect_files_from_git(root) {
        if !files.is_empty() {
            return files;
        }
    }
    let mut files = Vec::new();
    collect_files_recursive(root, root, &mut files);
    files
}

fn has_extension(rel: &Path, exts: &[&str]) -> bool {
    rel.extension()
        .and_then(|e| e.to_str())
        .map(|ext| {
            exts.iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(ext))
        })
        .unwrap_or(false)
}

fn is_text_repo_file(rel: &Path) -> bool {
    has_extension(rel, TEXT_EXTENSIONS)
        || rel
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| TEXT_FILE_NAMES.contains(&n))
}

fn is_forbidden_typography_char(ch: char) -> Option<&'static str> {
    match ch {
        '\u{FEFF}' => Some("U+FEFF BOM / zero-width no-break space"),
        '\u{2014}' => Some("U+2014 em dash"),
        '\u{2013}' => Some("U+2013 en dash"),
        '\u{2010}'..='\u{2012}' | '\u{2015}' => Some("Unicode dash/hyphen"),
        '\u{2212}' => Some("U+2212 Unicode minus sign"),
        '\u{00AB}' | '\u{00BB}' => Some("French guillemets"),
        '\u{2018}' | '\u{2019}' | '\u{201A}' => Some("Curly single quote"),
        '\u{201C}' | '\u{201D}' | '\u{201E}' => Some("Curly double quote"),
        '\u{2039}' | '\u{203A}' => Some("Single guillemets"),
        '\u{2026}' => Some("U+2026 ellipsis"),
        '\u{00A0}' => Some("U+00A0 non-breaking space"),
        '\u{202F}' => Some("U+202F narrow no-break space"),
        '\u{2009}' => Some("U+2009 thin space"),
        '\u{200B}' => Some("U+200B zero-width space"),
        '\u{0152}' | '\u{0153}' => Some("OE/oe ligature"),
        '\u{00C6}' | '\u{00E6}' => Some("AE/ae ligature"),
        _ => None,
    }
}

fn flatten_json_strings(prefix: &str, value: &Value, out: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let next = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };
                flatten_json_strings(&next, v, out);
            }
        }
        Value::String(s) => {
            out.insert(prefix.to_string(), s.clone());
        }
        other => panic!(
            "Unexpected non-object/non-string locale value at '{}': {}",
            prefix, other
        ),
    }
}

#[test]
fn recursive_traversal_reaches_nested_subdirectories() {
    let root = repo_root();
    let mut files = Vec::new();
    collect_files_recursive(&root, &root, &mut files);

    let normalized: BTreeSet<String> = files
        .iter()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();

    assert!(normalized.contains("README.md"));
    assert!(normalized.contains("docs/fr/architecture.md"));
    assert!(normalized.contains("crates/routeward-core/src/lib.rs"));
    assert!(normalized.contains("ui/src/services/ipc.ts"));
    assert!(normalized.contains("tests/linux/run-scenarios.sh"));
}

#[test]
fn repo_file_enumeration_reaches_nested_subdirectories_and_skips_worktrees() {
    let root = repo_root();
    let files = collect_repo_files(&root);

    let normalized: BTreeSet<String> = files
        .iter()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();

    assert!(normalized.contains("README.md"));
    assert!(normalized.contains("docs/fr/architecture.md"));
    assert!(normalized.contains("crates/routeward-core/src/lib.rs"));
    assert!(normalized.contains("ui/src/services/ipc.ts"));
    assert!(normalized.contains("packaging/linux/postinst"));
    assert!(
        normalized
            .iter()
            .all(|p| !p.starts_with(".claude/") && !p.starts_with("target/")),
        "enumeration must never return agent worktrees or build output"
    );
}

#[test]
fn repo_typography_encoding_and_mojibake_guard() {
    let root = repo_root();
    let files = collect_repo_files(&root);

    let mojibake_markers = [
        "\u{00C3}\u{00A9}",
        "\u{00C3}\u{00A8}",
        "\u{00C3}\u{00A0}",
        "\u{00C3}\u{00AA}",
        "\u{00C3}\u{00A7}",
        "\u{00C3}\u{00AE}",
        "\u{00C3}\u{00B4}",
        "\u{00E2}\u{20AC}",
    ];

    let mut violations = Vec::new();

    for rel in files.into_iter().filter(|p| is_text_repo_file(p)) {
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if rel_str == "crates/routeward-core/tests/repo_guards.rs" {
            continue;
        }
        let abs = root.join(&rel);
        let bytes = fs::read(&abs).unwrap_or_else(|e| panic!("Read failed {:?}: {}", abs, e));
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            violations.push(format!("{}:1: UTF-8 BOM detected", rel_str));
        }

        let content = String::from_utf8(bytes)
            .unwrap_or_else(|e| panic!("Invalid UTF-8 in {}: {}", rel_str, e));

        for (line_idx, line) in content.lines().enumerate() {
            let line_no = line_idx + 1;
            for (col_idx, ch) in line.chars().enumerate() {
                if let Some(reason) = is_forbidden_typography_char(ch) {
                    violations.push(format!(
                        "{}:{}:{}: forbidden {} ({:?})",
                        rel_str,
                        line_no,
                        col_idx + 1,
                        reason,
                        ch
                    ));
                }
            }
            for marker in mojibake_markers {
                if line.contains(marker) {
                    violations.push(format!(
                        "{}:{}: mojibake sequence detected",
                        rel_str, line_no
                    ));
                }
            }
            let lower = line.to_ascii_lowercase();
            if lower.contains(concat!("co-authored-", "by:"))
                || lower.contains(concat!("generated with ", "claude"))
            {
                violations.push(format!(
                    "{}:{}: attribution marker detected",
                    rel_str, line_no
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Typography/encoding guard violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn repo_apache_license_headers_guard() {
    let root = repo_root();
    let files = collect_repo_files(&root);

    let mut missing = Vec::new();
    for rel in files {
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let check = has_extension(&rel, SOURCE_HEADER_EXTENSIONS)
            || rel
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "Dockerfile");
        if !check || rel_str.ends_with(".d.ts") {
            continue;
        }
        let abs = root.join(&rel);
        let content =
            fs::read_to_string(&abs).unwrap_or_else(|e| panic!("Read failed {:?}: {}", abs, e));
        let header_slice: String = content
            .lines()
            .take(HEADER_SCAN_LINES)
            .collect::<Vec<_>>()
            .join("\n");
        if !header_slice.contains("Licensed under the Apache License, Version 2.0")
            || !header_slice.contains("Julien Bombled")
        {
            missing.push(rel_str);
        }
    }

    assert!(
        missing.is_empty(),
        "Files missing Apache 2.0 header:\n{}",
        missing.join("\n")
    );
}

#[test]
fn locales_en_and_fr_key_parity_and_doc_mirrors_guard() {
    let root = repo_root();
    let en_raw = fs::read_to_string(root.join("locales/en.json")).expect("read locales/en.json");
    let fr_raw = fs::read_to_string(root.join("locales/fr.json")).expect("read locales/fr.json");

    let en_val: Value = serde_json::from_str(&en_raw).expect("parse locales/en.json");
    let fr_val: Value = serde_json::from_str(&fr_raw).expect("parse locales/fr.json");

    let mut en_keys = BTreeMap::new();
    let mut fr_keys = BTreeMap::new();
    flatten_json_strings("", &en_val, &mut en_keys);
    flatten_json_strings("", &fr_val, &mut fr_keys);

    let en_set: BTreeSet<&String> = en_keys.keys().collect();
    let fr_set: BTreeSet<&String> = fr_keys.keys().collect();

    let only_en: Vec<&&String> = en_set.difference(&fr_set).collect();
    let only_fr: Vec<&&String> = fr_set.difference(&en_set).collect();
    assert!(
        only_en.is_empty() && only_fr.is_empty(),
        "Locale key mismatch: only_en={:?}, only_fr={:?}",
        only_en,
        only_fr
    );

    for (k, v) in en_keys.iter().chain(fr_keys.iter()) {
        assert!(!v.trim().is_empty(), "Empty locale translation for '{}'", k);
    }

    let doc_pairs = [
        ("README.md", "README.fr.md", "README.fr.md", "README.md"),
        (
            "CONTRIBUTING.md",
            "CONTRIBUTING.fr.md",
            "CONTRIBUTING.fr.md",
            "CONTRIBUTING.md",
        ),
        (
            "docs/architecture.md",
            "docs/fr/architecture.md",
            "fr/architecture.md",
            "../architecture.md",
        ),
        (
            "docs/build.md",
            "docs/fr/build.md",
            "fr/build.md",
            "../build.md",
        ),
        (
            "docs/maintenance.md",
            "docs/fr/maintenance.md",
            "fr/maintenance.md",
            "../maintenance.md",
        ),
        (
            "docs/troubleshooting.md",
            "docs/fr/troubleshooting.md",
            "fr/troubleshooting.md",
            "../troubleshooting.md",
        ),
        (
            "docs/windows-testing.md",
            "docs/fr/windows-testing.md",
            "fr/windows-testing.md",
            "../windows-testing.md",
        ),
    ];

    for (en_path, fr_path, expected_fr_link, expected_en_link) in doc_pairs {
        let en_top = fs::read_to_string(root.join(en_path))
            .unwrap_or_else(|e| panic!("read {}: {}", en_path, e));
        let fr_top = fs::read_to_string(root.join(fr_path))
            .unwrap_or_else(|e| panic!("read {}: {}", fr_path, e));
        let en_head = en_top.lines().take(5).collect::<Vec<_>>().join("\n");
        let fr_head = fr_top.lines().take(5).collect::<Vec<_>>().join("\n");
        assert!(
            en_head.contains(expected_fr_link),
            "{} top lines missing link to {}",
            en_path,
            expected_fr_link
        );
        assert!(
            fr_head.contains(expected_en_link),
            "{} top lines missing link to {}",
            fr_path,
            expected_en_link
        );
    }
}

fn flatten_locale_keys(path: &str, root: &Path) -> BTreeSet<String> {
    let raw =
        fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    let value: Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {}", path, e));
    let mut map = BTreeMap::new();
    flatten_json_strings("", &value, &mut map);
    map.into_keys().collect()
}

#[test]
fn every_english_locale_key_is_referenced_in_sources() {
    let root = repo_root();
    let keys = flatten_locale_keys("locales/en.json", &root);

    let mut corpus = String::new();
    for rel in collect_repo_files(&root) {
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let in_scope = LOCALE_REFERENCE_DIRS
            .iter()
            .any(|dir| rel_str.starts_with(&format!("{}/", dir)));
        if !in_scope || !has_extension(&rel, LOCALE_REFERENCE_EXTENSIONS) {
            continue;
        }
        if let Ok(content) = fs::read_to_string(root.join(&rel)) {
            corpus.push_str(&content);
            corpus.push('\n');
        }
    }
    assert!(
        corpus.contains("i18nKey"),
        "locale reference corpus must include the embedded configs"
    );

    let orphans: Vec<&String> = keys
        .iter()
        .filter(|key| {
            !DYNAMIC_LOCALE_KEY_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix))
                && !corpus.contains(key.as_str())
        })
        .collect();
    assert!(
        orphans.is_empty(),
        "locales/en.json keys never referenced in ui/src, apps/desktop/src, crates or configs:\n{}",
        orphans
            .iter()
            .map(|k| k.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Maps the workspace version (for example `2026.1116.0`) to its tag name (`v2026.1116.00`).
fn release_tag_for_workspace_version(cargo_toml: &str) -> String {
    let mut in_workspace_package = false;
    let mut version = None;
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_workspace_package = trimmed == "[workspace.package]";
            continue;
        }
        if in_workspace_package {
            if let Some(rest) = trimmed.strip_prefix("version") {
                let value = rest.trim_start().trim_start_matches('=').trim();
                version = Some(value.trim_matches('"').to_string());
                break;
            }
        }
    }
    let version = version.expect("workspace.package.version in Cargo.toml");
    let parts: Vec<&str> = version.split('.').collect();
    assert_eq!(parts.len(), 3, "unexpected workspace version {}", version);
    let day: u32 = parts[2].parse().expect("numeric day counter");
    format!("v{}.{}.{:02}", parts[0], parts[1], day)
}

#[test]
fn release_notes_exist_for_workspace_version_and_contain_no_arrows() {
    let root = repo_root();
    let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
    let tag = release_tag_for_workspace_version(&cargo_toml);

    let note = root.join(format!("docs/release-notes/{}.md", tag));
    assert!(
        note.is_file(),
        "missing release notes for the workspace version: docs/release-notes/{}.md",
        tag
    );

    let mut violations = Vec::new();
    for dir in RELEASE_NOTES_DIRS {
        let entries =
            fs::read_dir(root.join(dir)).unwrap_or_else(|e| panic!("read {}: {}", dir, e));
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let content = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Read failed {:?}: {}", path, e));
            let is_english = *dir == "docs/release-notes";
            for (line_idx, line) in content.lines().enumerate() {
                for ch in line.chars() {
                    let arrow = ('\u{2190}'..='\u{21FF}').contains(&ch)
                        || ('\u{27F0}'..='\u{27FF}').contains(&ch)
                        || ('\u{2900}'..='\u{297F}').contains(&ch)
                        || ('\u{2B00}'..='\u{2B11}').contains(&ch);
                    if arrow {
                        violations.push(format!(
                            "{}/{}:{}: arrow {:?} in release notes",
                            dir,
                            entry.file_name().to_string_lossy(),
                            line_idx + 1,
                            ch
                        ));
                    }
                    if is_english && !ch.is_ascii() {
                        violations.push(format!(
                            "{}/{}:{}: non-ASCII {:?} in English release notes",
                            dir,
                            entry.file_name().to_string_lossy(),
                            line_idx + 1,
                            ch
                        ));
                    }
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Release notes violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn release_tag_mapping_pads_the_day_counter() {
    let manifest = "[workspace.package]\nversion = \"2026.1116.0\"\n";
    assert_eq!(release_tag_for_workspace_version(manifest), "v2026.1116.00");
    let manifest = "[workspace.package]\nversion = \"2026.1115.3\"\n";
    assert_eq!(release_tag_for_workspace_version(manifest), "v2026.1115.03");
    let manifest = "[workspace.package]\nversion = \"2026.1201.12\"\n";
    assert_eq!(release_tag_for_workspace_version(manifest), "v2026.1201.12");
}
