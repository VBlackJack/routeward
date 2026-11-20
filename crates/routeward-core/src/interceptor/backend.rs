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

use crate::error::RouteWardResult;
use crate::interceptor::RouteWardController;
use std::collections::BTreeSet;

/// Pluggable OS packet interception backend abstraction.
///
/// Allows `RouteWardController` and `RuleEngine` to remain independent of the
/// underlying packet capture mechanism (for example `WinDivertInterceptor` today,
/// or a Windows Filtering Platform `WfpInterceptor` / Linux `NftablesTproxyInterceptor`
/// in future milestones).
pub trait Interceptor: Send + Sync {
    /// Returns the human-readable backend identifier (for example `"WinDivert"`).
    fn name(&self) -> &'static str;

    /// Starts packet capture and transparent redirection toward `controller`.
    fn start(&self, controller: RouteWardController) -> RouteWardResult<()>;

    /// Reapplies packet capture / firewall rules in-place without any permissive gap.
    fn reload(&self, controller: RouteWardController) -> RouteWardResult<()> {
        let _ = controller;
        Ok(())
    }

    /// Pushes the user ids of exempt DNS server processes into the firewall (Linux only; the
    /// other backends decide per packet). `block` is the subset an explicit Block rule drops.
    fn sync_dns_server_uids(
        &self,
        exempt: &BTreeSet<u32>,
        block: &BTreeSet<u32>,
    ) -> RouteWardResult<()> {
        let _ = (exempt, block);
        Ok(())
    }

    /// Stops packet capture and releases any kernel/OS handles immediately (fail-open).
    fn stop(&self);

    /// Returns `true` while the interception backend is actively filtering packets.
    fn is_active(&self) -> bool;
}
