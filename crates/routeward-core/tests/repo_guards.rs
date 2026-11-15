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

const SKIPPED_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "dist",
    "local",
    "logs",
    "third_party",
];

const TEXT_EXTENSIONS: &[&str] = &[
    "rs", "ts", "tsx", "js", "jsx", "css", "html", "md", "json", "toml", "yml", "yaml", "ps1",
    "sh", "py", "bat",
];

const SOURCE_HEADER_EXTENSIONS: &[&str] = &["rs", "ts", "tsx", "css", "ps1", "sh", "py"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn collect_files_recursive(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        panic!("Failed to read directory {:?}", dir);
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if path.is_dir() {
            if SKIPPED_DIRS.iter().any(|skip| *skip == name) {
                continue;
            }
            collect_files_recursive(root, &path, out);
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .expect("relative path")
                .to_path_buf();
            out.push(rel);
        }
    }
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
            .is_some_and(|n| n == "Dockerfile")
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
fn repo_typography_encoding_and_mojibake_guard() {
    let root = repo_root();
    let mut files = Vec::new();
    collect_files_recursive(&root, &root, &mut files);

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
    let mut files = Vec::new();
    collect_files_recursive(&root, &root, &mut files);

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
        let header_slice: String = content.lines().take(20).collect::<Vec<_>>().join("\n");
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
