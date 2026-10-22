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

pub mod commands;

use commands::DesktopCommandBridge;
use routeward_core::config::{ProfileConfig, SystemConstants};
use routeward_core::interceptor::RouteWardController;

const DEFAULT_DESKTOP_LOCALE: &str = "fr";

pub fn create_desktop_bridge() -> Result<DesktopCommandBridge, String> {
    let constants = SystemConstants::load_embedded().map_err(|e| e.to_string())?;
    let profile = ProfileConfig::load_embedded_default().map_err(|e| e.to_string())?;
    let controller = RouteWardController::new(constants, profile, DEFAULT_DESKTOP_LOCALE);
    controller.start_engine();
    let bridge = DesktopCommandBridge::new(controller);
    let _ = bridge.scan_os_sockets();
    Ok(bridge)
}
