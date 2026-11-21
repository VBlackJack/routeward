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

import { UI_CONFIG } from '../config/constants';
import {
  ProxyChain,
  ProxyNode,
  RoutingRule,
  RuleAction
} from '../types/routeward';

const FRIENDLY_APP_MAP: Record<string, string> = {
  'msedge.exe': 'Microsoft Edge',
  'firefox.exe': 'Mozilla Firefox',
  'chrome.exe': 'Google Chrome',
  'brave.exe': 'Brave Browser',
  'opera.exe': 'Opera',
  'vivaldi.exe': 'Vivaldi',
  'discord.exe': 'Discord',
  'telegram.exe': 'Telegram',
  'signal.exe': 'Signal',
  'slack.exe': 'Slack',
  'teams.exe': 'Microsoft Teams',
  'ms-teams.exe': 'Microsoft Teams',
  'zoom.exe': 'Zoom',
  'spotify.exe': 'Spotify',
  'vlc.exe': 'VLC Media Player',
  'obs64.exe': 'OBS Studio',
  'steam.exe': 'Steam',
  'epicgameslauncher.exe': 'Epic Games',
  'battle.net.exe': 'Battle.net',
  'code.exe': 'Visual Studio Code',
  'git.exe': 'Git',
  'node.exe': 'Node.js',
  'python.exe': 'Python',
  'docker.exe': 'Docker',
  'curl.exe': 'cURL',
  'svchost.exe': 'Windows System',
  'compattelrunner.exe': 'Windows Telemetry',
  'diagtrack': 'Windows Diagnostics'
};

export interface FriendlyAppInfo {
  displayName: string;
  technicalName: string | null;
}

/**
 * Resolves a human-friendly display name for common executables in Simple mode.
 * Unknown process names are returned as-is with `technicalName: null`.
 */
export function getFriendlyAppName(processName: string): FriendlyAppInfo {
  const clean = processName.trim();
  const key = clean.toLowerCase();
  const friendly = FRIENDLY_APP_MAP[key];
  if (friendly) {
    return { displayName: friendly, technicalName: clean };
  }
  return { displayName: clean, technicalName: null };
}

/**
 * Maps a raw technical connection error detail to a localized beginner-friendly explanation key.
 */
export function getHumanErrorKey(errorDetail?: string | null): string {
  if (!errorDetail) {
    return 'troubleshoot.reasons.blocked_by_rule';
  }
  const lower = errorDetail.toLowerCase();
  if (/auth|407|credential|password|user/.test(lower)) {
    return 'troubleshoot.reasons.auth';
  }
  if (/kill-?switch/.test(lower)) {
    return 'troubleshoot.reasons.killswitch';
  }
  if (/udp|quic/.test(lower)) {
    return 'troubleshoot.reasons.udp';
  }
  if (/dns|resolve|nxdomain/.test(lower)) {
    return 'troubleshoot.reasons.dns';
  }
  if (/timeout|timed out/.test(lower)) {
    return 'troubleshoot.reasons.timeout';
  }
  if (/unreachable|refused|reset|upstream|proxy/.test(lower)) {
    return 'troubleshoot.reasons.unreachable';
  }
  return 'troubleshoot.reasons.generic';
}

/**
 * Resolves the target action for a "Via Proxy" rule in Simple mode:
 * uses the active Simple Failover chain when enabled and backed by enabled proxies,
 * otherwise falls back to the first enabled proxy.
 */
export function resolveSimpleProxyAction(
  proxies: ProxyNode[],
  chains: ProxyChain[]
): RuleAction | null {
  const enabledProxies = proxies.filter((p) => p.enabled);
  if (enabledProxies.length === 0) {
    return null;
  }
  const enabledIds = new Set(enabledProxies.map((p) => p.id));
  const failoverChain = chains.find(
    (c) =>
      c.enabled &&
      (c.id === UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID || c.strategy === 'failover') &&
      c.proxyIds.some((pid) => enabledIds.has(pid))
  );
  if (failoverChain) {
    return { type: 'chain', targetId: failoverChain.id };
  }
  return { type: 'proxy', targetId: enabledProxies[0].id };
}

/**
 * Returns the first earlier enabled rule that would shadow `rule` with a different action
 * (for example, a broad browser rule at priority 10 overriding a site-specific rule at priority 50).
 */
export function findShadowingRule(
  rule: RoutingRule,
  allRules: RoutingRule[]
): RoutingRule | null {
  if (!rule.enabled) {
    return null;
  }
  const ordered = [...allRules]
    .filter((r) => r.enabled)
    .sort((a, b) => a.priority - b.priority);

  const targetIdx = ordered.findIndex((r) => r.id === rule.id);
  if (targetIdx <= 0) {
    return null;
  }

  const ruleProcs = new Set(rule.processPatterns.map((p) => p.toLowerCase()));
  for (let i = 0; i < targetIdx; i += 1) {
    const candidate = ordered[i];
    if (candidate.action.type === rule.action.type) {
      continue;
    }
    if (candidate.domainPatterns.length > 0 || candidate.ipCidrs.length > 0) {
      continue;
    }
    const candidateMatchesAllProcs = candidate.processPatterns.length === 0;
    const processesOverlap =
      candidateMatchesAllProcs ||
      ruleProcs.size === 0 ||
      candidate.processPatterns.some((p) => ruleProcs.has(p.toLowerCase()));
    if (processesOverlap && (rule.domainPatterns.length > 0 || candidateMatchesAllProcs)) {
      return candidate;
    }
  }
  return null;
}
