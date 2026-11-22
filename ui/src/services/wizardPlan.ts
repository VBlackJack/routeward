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

export type WizardGoal = 'privacy' | 'work' | 'gaming';

/**
 * Presets the setup assistant applies for a goal. Rules that need a proxy are only listed when
 * one is configured, so the summary and the created rules always agree.
 */
export function getWizardPresetIds(
  goal: WizardGoal,
  hasProxy: boolean
): string[] {
  if (goal === 'privacy') {
    return [
      ...(hasProxy ? ['preset-privacy-browsers'] : []),
      'preset-block-os-telemetry',
      'preset-rfc1918-direct'
    ];
  }
  if (goal === 'work') {
    return [
      ...(hasProxy ? ['preset-dev-toolchains'] : []),
      'preset-rfc1918-direct'
    ];
  }
  return [
    ...(hasProxy ? ['preset-privacy-browsers'] : []),
    'preset-rfc1918-direct'
  ];
}

/**
 * Locale keys of the sentences that describe exactly what the assistant will do. A sentence is
 * only listed when a rule really does it (no tracker blocking promise without a blocking rule).
 */
export function buildWizardSummaryKeys(
  goal: WizardGoal,
  hasProxy: boolean
): string[] {
  const presets = getWizardPresetIds(goal, hasProxy);
  const keys: string[] = [];
  if (goal === 'gaming') {
    keys.push('wizard.summary.games_direct');
  }
  if (!hasProxy) {
    keys.push('wizard.summary.no_proxy_ip_visible');
  }
  if (presets.includes('preset-privacy-browsers')) {
    keys.push('wizard.summary.browsers_via_proxy');
  }
  if (presets.includes('preset-dev-toolchains')) {
    keys.push('wizard.summary.work_tools_via_proxy');
  }
  if (presets.includes('preset-block-os-telemetry')) {
    keys.push('wizard.summary.block_telemetry');
  }
  if (presets.includes('preset-rfc1918-direct')) {
    keys.push('wizard.summary.local_network_direct');
  }
  return keys;
}

/** Counts the proxies of `after` that were not in `before` (what an import really added). */
export function countAddedProxies(
  before: ReadonlyArray<{ id: string }>,
  after: ReadonlyArray<{ id: string }>
): number {
  const known = new Set(before.map((p) => p.id));
  return after.filter((p) => !known.has(p.id)).length;
}
