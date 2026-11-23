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
    "sh", "py", "bat", "wxs", "svg", "rc", "template", "service", "desktop",
];

/// Extensionless packaging scripts that are scanned as text (maintainer scripts of the .deb).
const TEXT_FILE_NAMES: &[&str] = &["Dockerfile", "postinst", "prerm", "postrm", ".env.example"];

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
    // BlockedView.tsx, activityWhy.ts: `blocked.reasons.${reason}.title|body` (see blockReason.ts)
    "blocked.reasons.",
    // AnalyzerPanel.tsx: `analyzer.findings.${code}.title|body|fix` (codes come from the daemon)
    "analyzer.findings.",
    // DiagnosticExportModal.tsx: `diagnostics.export.redaction.${code}` (codes come from the daemon)
    "diagnostics.export.redaction.",
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
                } else if ch.is_control() && ch != '\t' {
                    violations.push(format!(
                        "{}:{}:{}: unexpected control character U+{:04X}",
                        rel_str,
                        line_no,
                        col_idx + 1,
                        ch as u32
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

/// i18next plural category suffixes; sources reference the base key and pass `count`.
const PLURAL_KEY_SUFFIXES: &[&str] = &["_zero", "_one", "_two", "_few", "_many", "_other"];

/// True when `key` itself, or (for a plural-suffixed key) its base key, appears in `corpus`.
fn locale_key_is_referenced(key: &str, corpus: &str) -> bool {
    if corpus.contains(key) {
        return true;
    }
    PLURAL_KEY_SUFFIXES
        .iter()
        .filter_map(|suffix| key.strip_suffix(suffix))
        .any(|base| !base.is_empty() && corpus.contains(base))
}

#[test]
fn plural_locale_keys_are_accepted_through_their_base_key_only() {
    assert!(locale_key_is_referenced(
        "a.count_other",
        "t('a.count', { count })"
    ));
    assert!(locale_key_is_referenced("a.count_one", "t('a.count')"));
    assert!(locale_key_is_referenced("a.exact_one", "a.exact_one"));
    assert!(!locale_key_is_referenced("a.count_one", "t('a.other')"));
    assert!(!locale_key_is_referenced("a.count_other", ""));
    assert!(!locale_key_is_referenced("a.count_extra", "t('a.count')"));
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
                && !locale_key_is_referenced(key, &corpus)
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
    let month_day: u32 = parts[1].parse().expect("numeric month-day");
    let day: u32 = parts[2].parse().expect("numeric day counter");
    format!("v{}.{:04}.{:02}", parts[0], month_day, day)
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
    let manifest = "[workspace.package]\nversion = \"2027.105.0\"\n";
    assert_eq!(release_tag_for_workspace_version(manifest), "v2027.0105.00");
}

/// Returns the opening tags named `tag` (for example `<Custom `) of an XML text, each as one
/// string from `<` to the closing `>`; quoted attribute values never end a tag early.
fn xml_tags<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(tag) {
        let tail = &rest[start..];
        let mut in_quotes = false;
        let mut end = tail.len();
        for (idx, ch) in tail.char_indices() {
            match ch {
                '"' => in_quotes = !in_quotes,
                '>' if !in_quotes => {
                    end = idx + 1;
                    break;
                }
                _ => {}
            }
        }
        out.push(&tail[..end]);
        rest = &tail[end..];
    }
    out
}

/// Value of the attribute `name` inside one tag string.
fn xml_attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!(" {name}=\"");
    let from = tag.find(&needle)? + needle.len();
    let len = tag[from..].find('"')?;
    Some(&tag[from..from + len])
}

fn tag_with_attr<'a>(tags: &[&'a str], name: &str, value: &str) -> &'a str {
    tags.iter()
        .copied()
        .find(|tag| xml_attr(tag, name) == Some(value))
        .unwrap_or_else(|| panic!("no tag with {name}=\"{value}\""))
}

/// Value of `const NAME: &str = r"...";` (or a plain string literal) in a Rust source text.
fn rust_str_const(source: &str, name: &str) -> String {
    let needle = format!("const {name}: &str = ");
    let from = source
        .find(&needle)
        .unwrap_or_else(|| panic!("constant {name} not found"))
        + needle.len();
    let literal = source[from..].trim_start_matches('r');
    let body = literal.strip_prefix('"').expect("string literal");
    let end = body.find('"').expect("closing quote");
    body[..end].to_string()
}

#[test]
fn msi_upgrade_keeps_protection_actions_are_wired_safely() {
    const CAPTURE_ACTION: &str = "CaptureOldProtectionStatus";
    const DECIDE_ACTION: &str = "MigrateUpgradeState";
    const CMD_LINE_PROPERTY: &str = "WixQuietExecCmdLine";
    const CMD_LINE_ACTION: &str = "SetRouteWardCaptureCmdLine";
    const OLD_CLI_PROPERTY: &str = "RouteWardOldCli";
    const ESCAPED_OLD_CLI_REFERENCE: &str = "[\\[]RouteWardOldCli[\\]]";
    const ENDS_WITH_OPERATOR: &str = "&gt;&gt;";
    let wxs = fs::read_to_string(repo_root().join("packaging/windows/RouteWard.wxs"))
        .expect("RouteWard.wxs");

    // The default schedule: the afterInstallInitialize one makes a deferred action precede
    // RemoveExistingProducts, which Windows Installer rejects with error 2613.
    let upgrade = xml_tags(&wxs, "<MajorUpgrade");
    assert_eq!(upgrade.len(), 1);
    assert!(
        matches!(
            xml_attr(upgrade[0], "Schedule"),
            None | Some("afterInstallValidate")
        ),
        "MajorUpgrade must keep the default schedule: {}",
        upgrade[0]
    );

    let sequence_rows = xml_tags(&wxs, "<Custom ");
    let actions = xml_tags(&wxs, "<CustomAction");
    let set_properties = xml_tags(&wxs, "<SetProperty");

    // Exactly one capture action, immediate and impersonated, before InstallValidate.
    assert_eq!(
        actions
            .iter()
            .filter(|tag| xml_attr(tag, "Id").is_some_and(|id| id.starts_with("Capture")))
            .count(),
        1,
        "exactly one capture action is expected"
    );
    let capture = tag_with_attr(&actions, "Id", CAPTURE_ACTION);
    assert_eq!(xml_attr(capture, "DllEntry"), Some("WixQuietExec"));
    assert_eq!(xml_attr(capture, "Return"), Some("ignore"));
    assert!(
        matches!(xml_attr(capture, "Execute"), None | Some("immediate")),
        "the capture must be immediate (a deferred one causes error 2613): {capture}"
    );
    assert!(
        xml_attr(capture, "Impersonate").is_none(),
        "the capture runs as the installing user: {capture}"
    );
    let capture_row = tag_with_attr(&sequence_rows, "Action", CAPTURE_ACTION);
    assert_eq!(xml_attr(capture_row, "Before"), Some("InstallValidate"));
    let capture_condition = xml_attr(capture_row, "Condition").expect("capture condition");
    for needle in [
        "NOT REMOVE",
        "WIX_UPGRADE_DETECTED",
        "ROUTEWARD_OLD_INSTALLDIR",
    ] {
        assert!(
            capture_condition.contains(needle),
            "capture condition lacks {needle}: {capture_condition}"
        );
    }

    // Its command line is set through the fixed property WixQuietExec reads in immediate mode.
    let cmd_line = tag_with_attr(&set_properties, "Id", CMD_LINE_PROPERTY);
    assert_eq!(xml_attr(cmd_line, "Action"), Some(CMD_LINE_ACTION));
    assert_eq!(xml_attr(cmd_line, "Before"), Some(CAPTURE_ACTION));
    assert_eq!(xml_attr(cmd_line, "Sequence"), Some("execute"));
    assert_eq!(xml_attr(cmd_line, "Condition"), Some(capture_condition));
    let migration_source = fs::read_to_string(
        repo_root().join("crates/routeward-core/src/system/upgrade_migration.rs"),
    )
    .expect("upgrade_migration.rs");
    let marker_key = rust_str_const(&migration_source, "UPGRADE_MARKER_SUBKEY");
    let marker_value = rust_str_const(&migration_source, "UPGRADE_MARKER_VALUE");
    let hkcu_key = format!("HKCU\\{marker_key}");
    let value = xml_attr(cmd_line, "Value").expect("capture command line");
    for needle in [
        format!("reg delete {hkcu_key}"),
        "findstr /c:".to_string(),
        format!("reg add {hkcu_key} /v {marker_value} /t REG_DWORD /d 1"),
        ESCAPED_OLD_CLI_REFERENCE.to_string(),
    ] {
        assert!(
            value.contains(&needle),
            "capture command line lacks `{needle}`: {value}"
        );
    }
    assert!(
        value.starts_with("&quot;"),
        "WixQuietExec requires a command line that starts with a quote: {value}"
    );

    // The old CLI path comes from two mutually exclusive rows, resolved before the setter above.
    let old_cli: Vec<&str> = set_properties
        .iter()
        .copied()
        .filter(|tag| xml_attr(tag, "Id") == Some(OLD_CLI_PROPERTY))
        .collect();
    assert_eq!(old_cli.len(), 2, "one row per trailing-backslash case");
    for tag in &old_cli {
        assert_eq!(xml_attr(tag, "Before"), Some(CMD_LINE_ACTION), "{tag}");
        assert_eq!(xml_attr(tag, "Sequence"), Some("execute"), "{tag}");
        let condition = xml_attr(tag, "Condition").expect("old CLI condition");
        assert!(condition.contains(ENDS_WITH_OPERATOR), "{condition}");
        assert!(condition.contains("NOT REMOVE"), "{condition}");
    }
    let conditions: Vec<&str> = old_cli
        .iter()
        .map(|tag| xml_attr(tag, "Condition").unwrap())
        .collect();
    assert_ne!(
        xml_attr(old_cli[0], "Action"),
        xml_attr(old_cli[1], "Action")
    );
    assert!(
        conditions.iter().filter(|c| c.contains("NOT (")).count() == 1
            && conditions.iter().filter(|c| !c.contains("NOT (")).count() == 1,
        "the two conditions must be mutually exclusive: {conditions:?}"
    );

    // The decision runs in the commit phase, as SYSTEM, through WixQuietExec.
    let decide_row = tag_with_attr(&sequence_rows, "Action", DECIDE_ACTION);
    assert_eq!(xml_attr(decide_row, "Before"), Some("InstallFinalize"));
    let decide_condition = xml_attr(decide_row, "Condition").expect("decide condition");
    for needle in [
        "NOT REMOVE",
        "WIX_UPGRADE_DETECTED",
        "ROUTEWARD_OLD_INSTALLDIR",
    ] {
        assert!(
            decide_condition.contains(needle),
            "decide condition lacks {needle}: {decide_condition}"
        );
    }
    let decide = tag_with_attr(&actions, "Id", DECIDE_ACTION);
    assert_eq!(xml_attr(decide, "Execute"), Some("commit"));
    assert_eq!(xml_attr(decide, "Impersonate"), Some("no"));
    assert_eq!(xml_attr(decide, "Return"), Some("ignore"));
    assert_eq!(xml_attr(decide, "DllEntry"), Some("WixQuietExec"));
    assert!(
        xml_attr(decide, "FileRef").is_none(),
        "a FileRef exe action drops the stderr log"
    );
    let decide_set = tag_with_attr(&set_properties, "Id", DECIDE_ACTION);
    assert_eq!(xml_attr(decide_set, "Before"), Some(DECIDE_ACTION));
    assert_eq!(xml_attr(decide_set, "Sequence"), Some("execute"));
    assert_eq!(xml_attr(decide_set, "Condition"), Some(decide_condition));
    assert!(
        xml_attr(decide_set, "Value")
            .expect("decide command line")
            .contains("--user-sid [UserSID]"),
        "the migration must be told whose marker to read"
    );

    // A brace inside a Formatted value starts a reference; it must be written as an escape.
    for tag in &set_properties {
        let value = xml_attr(tag, "Value").unwrap_or("");
        let unescaped = value.replace("[\\{]", "").replace("[\\}]", "");
        assert!(
            !unescaped.contains('{') && !unescaped.contains('}'),
            "unescaped brace in a SetProperty value: {value}"
        );
    }
}

#[test]
fn rust_str_const_reads_raw_and_plain_literals() {
    let source = "pub const A: &str = r\"x\\y\";\nconst B: &str = \"z\";";
    assert_eq!(rust_str_const(source, "A"), "x\\y");
    assert_eq!(rust_str_const(source, "B"), "z");
}

#[test]
fn xml_tag_scanner_ignores_quoted_angle_brackets() {
    let xml = r#"<A One="a>b" Two="c"/><A One="d"/>"#;
    let tags = xml_tags(xml, "<A");
    assert_eq!(tags.len(), 2);
    assert_eq!(xml_attr(tags[0], "Two"), Some("c"));
    assert_eq!(xml_attr(tags[1], "One"), Some("d"));
}

/// Directory whose sources may build `Blocked` records by hand (the one constructor lives there).
const BLOCKED_LITERAL_ALLOWED_DIR: &str = "crates/routeward-core/src/telemetry/";

/// Line numbers (1-based) where a `Blocked` status is written as a struct field, outside the
/// `#[cfg(test)]` tail of the file.
fn blocked_status_literal_lines(source: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        let compact: String = line.split_whitespace().collect();
        if compact.contains("status:ConnectionStatus::Blocked") {
            lines.push(idx + 1);
        }
    }
    lines
}

#[test]
fn blocked_status_literal_scanner_ignores_comparisons_and_test_modules() {
    let sample = "let a = c.status == ConnectionStatus::Blocked;\n\
                  let b = X { status: ConnectionStatus::Blocked };\n\
                  #[cfg(test)]\n\
                  mod tests { let c = X { status: ConnectionStatus::Blocked }; }\n";
    assert_eq!(blocked_status_literal_lines(sample), vec![2]);
}

#[test]
fn blocked_connections_are_only_built_through_the_telemetry_constructor() {
    let root = repo_root();
    let files = collect_repo_files(&root);
    let mut scanned_interceptor = false;
    let mut offenders = Vec::new();
    for rel in files {
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if !rel_str.ends_with(".rs")
            || !(rel_str.starts_with("crates/") || rel_str.starts_with("apps/"))
            || rel_str.contains("/tests/")
            || rel_str.ends_with("/tests.rs")
            || rel_str.starts_with(BLOCKED_LITERAL_ALLOWED_DIR)
        {
            continue;
        }
        if rel_str == "crates/routeward-core/src/interceptor/udp_relay.rs" {
            scanned_interceptor = true;
        }
        let source = fs::read_to_string(root.join(&rel))
            .unwrap_or_else(|e| panic!("read {}: {}", rel_str, e));
        for line in blocked_status_literal_lines(&source) {
            offenders.push(format!("{rel_str}:{line}"));
        }
    }
    assert!(
        scanned_interceptor,
        "the guard must reach the interceptor sources"
    );
    assert!(
        offenders.is_empty(),
        "build blocked connections with TrackedConnection::blocked(BlockedRecord) so a reason is \
         always recorded; hand-written literals found at: {offenders:?}"
    );
}
