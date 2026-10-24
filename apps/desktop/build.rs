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

fn main() {
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
