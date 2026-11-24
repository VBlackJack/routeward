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

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

fn emit_embedded_ui_assets() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let assets_dir = manifest_dir.join("../../ui/dist/assets");
    println!("cargo:rerun-if-changed={}", assets_dir.display());

    let mut files: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(entries) = fs::read_dir(&assets_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.ends_with(".js") || name.ends_with(".css") {
                println!("cargo:rerun-if-changed={}", path.display());
                files.push((name.to_string(), path));
            }
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut code = String::from(
        "fn lookup_embedded_ui_asset(path: &str) -> Option<(&'static str, &'static [u8])> {\n    match path {\n",
    );
    for (name, abs_path) in files {
        let content_type = if name.ends_with(".css") {
            "text/css; charset=utf-8"
        } else {
            "application/javascript; charset=utf-8"
        };
        let canonical = fs::canonicalize(&abs_path).unwrap_or(abs_path);
        let path_str = canonical.to_string_lossy();
        let _ = writeln!(
            code,
            "        \"/assets/{name}\" => Some(({content_type:?}, include_bytes!({path_str:?}))),"
        );
    }
    code.push_str("        _ => None,\n    }\n}\n");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = Path::new(&out_dir).join("embedded_ui_assets.rs");
    fs::write(&dest, code).expect("write embedded_ui_assets.rs");
}

fn main() {
    emit_embedded_ui_assets();

    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=../../assets/branding/routeward.rc");
        println!("cargo:rerun-if-changed=../../assets/branding/routeward.ico");
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            embed_resource::compile("../../assets/branding/routeward.rc", embed_resource::NONE)
                .manifest_required()
                .expect("Failed to compile Windows icon resource");
        }
    }
}
