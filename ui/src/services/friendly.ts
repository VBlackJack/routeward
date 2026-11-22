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
  ProxyProtocol,
  RoutingRule,
  RuleAction
} from '../types/routeward';
import { parseSingleProxyUri } from './uri';

/** Minimal translator signature accepted by the helpers below (i18next `t` satisfies it). */
export type Translate = (
  key: string,
  options?: Record<string, unknown>
) => string;

const SCHEMELESS_PROXY_LINK_PATTERN =
  /^(?:[^\s@/:]+(?::[^\s@/]*)?@)?(?:\[[0-9a-f:.]+\]|[^\s@/:[\]]+):\d{1,5}(?:#.*)?$/i;
const HOST_AND_PORT_PATTERN = /^([^\s:/@[\]]+):(\d{1,5})$/;
const RULE_SLUG_PATTERN = /[^a-z0-9]+/g;
const REGEX_SPECIAL_CHARS_PATTERN = /[.+?^${}()|[\]\\]/g;

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
 * uses the Simple Failover chain (never an Expert chain) when enabled and backed by
 * enabled proxies, otherwise falls back to the first enabled proxy.
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
      c.id === UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID &&
      c.proxyIds.some((pid) => enabledIds.has(pid))
  );
  if (failoverChain) {
    return { type: 'chain', targetId: failoverChain.id };
  }
  return { type: 'proxy', targetId: enabledProxies[0].id };
}

/** Lowercase slug used inside deterministic rule ids. */
export function slugifyRuleKey(value: string): string {
  return value.toLowerCase().replace(RULE_SLUG_PATTERN, '-');
}

/** True when the rule id comes from a Simple entry point (the only rules Simple actions may retarget). */
export function isSimpleCreatedRuleId(id: string): boolean {
  return Object.values(UI_CONFIG.SIMPLE_RULE_ID_PREFIXES).some((prefix) =>
    id.startsWith(prefix)
  );
}

/** Deterministic id of the single Simple rule that targets one application. */
export function buildSimpleAppRuleId(processName: string): string {
  return `${UI_CONFIG.SIMPLE_RULE_ID_PREFIXES.APP}${slugifyRuleKey(processName)}`;
}

/** Deterministic id of the single Simple rule that targets one website (or a list of them). */
export function buildSimpleSiteRuleId(domains: string[]): string {
  const slug = slugifyRuleKey(domains.join('-')).replace(/^-+|-+$/g, '');
  return `${UI_CONFIG.SIMPLE_RULE_ID_PREFIXES.SITE}${slug}`;
}

function sameStringSet(a: string[], b: string[]): boolean {
  if (a.length !== b.length) {
    return false;
  }
  const left = new Set(a.map((v) => v.toLowerCase()));
  return b.every((v) => left.has(v.toLowerCase()));
}

/**
 * Resolves the id a Simple rule must use so that repeating a choice replaces the previous rule:
 * an existing Simple rule with the very same criteria keeps its id (including ids from older
 * versions), otherwise the id is derived deterministically from the criteria.
 */
export function resolveSimpleRuleId(
  existingRules: RoutingRule[],
  processPatterns: string[],
  domainPatterns: string[]
): string {
  const previous = existingRules.find(
    (r) =>
      isSimpleCreatedRuleId(r.id) &&
      !r.id.startsWith(UI_CONFIG.SIMPLE_RULE_ID_PREFIXES.VISUAL) &&
      r.ipCidrs.length === 0 &&
      r.portRanges.length === 0 &&
      r.protocol === 'any' &&
      sameStringSet(r.processPatterns, processPatterns) &&
      sameStringSet(r.domainPatterns, domainPatterns)
  );
  if (previous) {
    return previous.id;
  }
  if (processPatterns.length === 1 && domainPatterns.length === 0) {
    return buildSimpleAppRuleId(processPatterns[0]);
  }
  if (processPatterns.length === 0) {
    return buildSimpleSiteRuleId(domainPatterns);
  }
  return `${buildSimpleAppRuleId(processPatterns.join('-'))}--${slugifyRuleKey(
    domainPatterns.join('-')
  )}`;
}

/** Builds the single Simple rule that routes one application. */
export function buildSimpleAppRule(params: {
  processName: string;
  action: RuleAction;
  existingRules?: RoutingRule[];
}): RoutingRule {
  const { processName, action, existingRules = [] } = params;
  return {
    id: resolveSimpleRuleId(existingRules, [processName], []),
    name: getFriendlyAppName(processName).displayName,
    enabled: true,
    priority: UI_CONFIG.SIMPLE_APP_RULE_PRIORITY,
    processPatterns: [processName],
    domainPatterns: [],
    ipCidrs: [],
    portRanges: [],
    protocol: 'any',
    action
  };
}

function matchesProcessPattern(pattern: string, processName: string): boolean {
  const p = pattern.trim().toLowerCase();
  const name = processName.trim().toLowerCase();
  if (!p || p.startsWith('!') || p.startsWith('regex:')) {
    return false;
  }
  if (!p.includes('*')) {
    return p === name;
  }
  const escaped = p
    .split('*')
    .map((chunk) => chunk.replace(REGEX_SPECIAL_CHARS_PATTERN, '\\$&'))
    .join('.*');
  return new RegExp(`^${escaped}$`).test(name);
}

/**
 * Returns the enabled whole-application rule that actually decides how `processName` connects
 * (lowest priority number wins), whether it is a single-app rule or a category rule.
 */
export function resolveEffectiveAppRule(
  processName: string,
  rules: RoutingRule[]
): RoutingRule | null {
  const candidates = rules
    .map((rule, index) => ({ rule, index }))
    .filter(
      ({ rule }) =>
        rule.enabled &&
        rule.domainPatterns.length === 0 &&
        rule.ipCidrs.length === 0 &&
        rule.portRanges.length === 0 &&
        rule.protocol === 'any' &&
        (rule.processPatterns.length === 0 ||
          rule.processPatterns.some((p) => matchesProcessPattern(p, processName)))
    )
    .sort((a, b) => a.rule.priority - b.rule.priority || a.index - b.index);
  return candidates[0]?.rule ?? null;
}

/** Maps a rule action to the three choices offered to beginners (a backup chain counts as proxy). */
export function toSimpleActionChoice(
  action: RuleAction
): 'proxy' | 'direct' | 'block' {
  return action.type === 'chain' ? 'proxy' : action.type;
}

/** Shows the engine fallback rule name through a localized label. */
export function localizeEngineRuleName(name: string, t: Translate): string {
  return name === UI_CONFIG.ENGINE_DEFAULT_RULE_NAME
    ? t('rules.generated.default_policy')
    : name;
}

/**
 * Returns the first earlier enabled rule that would shadow `rule` with a different action
 * (for example, a broad browser rule at priority 10 overriding a site-specific rule at priority 50,
 * or a browser category rule overriding a rule for one browser).
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
    if (
      candidate.domainPatterns.length > 0 ||
      candidate.ipCidrs.length > 0 ||
      candidate.portRanges.length > 0
    ) {
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
    // An application rule hidden behind a category rule that lists the same application.
    if (
      rule.domainPatterns.length === 0 &&
      rule.processPatterns.some((proc) =>
        candidate.processPatterns.some((p) => matchesProcessPattern(p, proc))
      )
    ) {
      return candidate;
    }
  }
  return null;
}

export interface ProxyRemovalPlan {
  /** Proxy that takes over the apps of the removed one, or null when none is left. */
  newPrimary: ProxyNode | null;
  /** Rules (as they are now) that point at the removed proxy or at a chain that dies with it. */
  affectedRules: RoutingRule[];
  /** Number of affected rules that are currently enabled. */
  affectedEnabledCount: number;
  /** The Simple failover chain must be removed because fewer than two proxies stay. */
  removeFailoverChain: boolean;
}

/**
 * Plans what happens to rules when a proxy is deleted: affected rules move to the new primary
 * proxy when one exists, otherwise they are disabled (never switched to a direct connection,
 * which would expose the real IP address).
 */
export function planProxyRemoval(
  proxyId: string,
  proxies: ProxyNode[],
  chains: ProxyChain[],
  rules: RoutingRule[]
): ProxyRemovalPlan {
  const remainingEnabled = proxies.filter((p) => p.enabled && p.id !== proxyId);
  const newPrimary = remainingEnabled[0] ?? null;
  const failoverChain = chains.find(
    (c) => c.id === UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID
  );
  const removeFailoverChain = Boolean(failoverChain) && remainingEnabled.length < 2;
  const deadChains = new Set<string>();
  if (failoverChain && removeFailoverChain) {
    deadChains.add(failoverChain.id);
  }
  for (const chain of chains) {
    if (chain.proxyIds.every((pid) => pid === proxyId)) {
      deadChains.add(chain.id);
    }
  }
  const affectedRules = rules.filter(
    (r) =>
      (r.action.type === 'proxy' && r.action.targetId === proxyId) ||
      (r.action.type === 'chain' &&
        Boolean(r.action.targetId) &&
        deadChains.has(r.action.targetId as string))
  );
  return {
    newPrimary,
    affectedRules,
    affectedEnabledCount: affectedRules.filter((r) => r.enabled).length,
    removeFailoverChain
  };
}

/** Rule as it must be saved after `planProxyRemoval`: retargeted to the new primary, else disabled. */
export function applyProxyRemovalToRule(
  rule: RoutingRule,
  plan: ProxyRemovalPlan
): RoutingRule {
  if (plan.newPrimary) {
    return { ...rule, action: { type: 'proxy', targetId: plan.newPrimary.id } };
  }
  return { ...rule, enabled: false };
}

/**
 * Parses a proxy link typed or pasted by a beginner. Accepts full links (`socks5://user:pw@host:1080`)
 * and links without a scheme (`1.2.3.4:8080`, `user:pw@host:8080`), which use `defaultProtocol`.
 */
export function parseLooseProxyLink(
  raw: string,
  defaultProtocol: ProxyProtocol
): ProxyNode | null {
  const text = raw.trim();
  if (!text) {
    return null;
  }
  if (text.includes('://')) {
    return parseSingleProxyUri(text);
  }
  if (!SCHEMELESS_PROXY_LINK_PATTERN.test(text)) {
    return null;
  }
  return parseSingleProxyUri(`${defaultProtocol}://${text}`);
}

/** Splits `host:port` typed in a host field; returns null when the text is not that shape. */
export function splitHostAndPort(
  raw: string
): { host: string; port: number } | null {
  const match = HOST_AND_PORT_PATTERN.exec(raw.trim());
  if (!match) {
    return null;
  }
  const port = Number(match[2]);
  if (port < 1 || port > UI_CONFIG.MAX_PORT) {
    return null;
  }
  return { host: match[1], port };
}

/** Prefixes scheme-less `host:port` lines of a batch import with `defaultProtocol`. */
export function normalizeProxyImportText(
  raw: string,
  defaultProtocol: ProxyProtocol
): string {
  return raw
    .split('\n')
    .map((line) => {
      const trimmed = line.trim();
      return trimmed &&
        !trimmed.startsWith('#') &&
        !trimmed.includes('://') &&
        SCHEMELESS_PROXY_LINK_PATTERN.test(trimmed)
        ? `${defaultProtocol}://${trimmed}`
        : line;
    })
    .join('\n');
}
