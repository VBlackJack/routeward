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
  BlockReason,
  ConnectionRequest,
  ProxyChain,
  ProxyNode,
  RoutingRule,
  RuleAction,
  TransportProtocol
} from '../types/routeward';
import { BlockFix, describeBlockReason } from './blockReason';
import {
  getFriendlyAppName,
  resolveSimpleProxyAction,
  slugifyRuleKey,
  Translate
} from './friendly';

/** How long an exception lasts. "always" leaves the rule without an expiry. */
export type UnblockDuration = 'minutes15' | 'hour1' | 'always';

export const UNBLOCK_DURATIONS: readonly UnblockDuration[] = [
  'minutes15',
  'hour1',
  'always'
];

const DURATION_MS: Record<Exclude<UnblockDuration, 'always'>, number> = {
  minutes15: UI_CONFIG.UNBLOCK_SHORT_DURATION_MS,
  hour1: UI_CONFIG.UNBLOCK_LONG_DURATION_MS
};

/** Rule ids a Simple screen creates for one app or one site: the only ones changed in place. */
const IN_PLACE_RULE_PREFIXES: readonly string[] = [
  UI_CONFIG.SIMPLE_RULE_ID_PREFIXES.APP,
  UI_CONFIG.SIMPLE_RULE_ID_PREFIXES.SITE,
  UI_CONFIG.SIMPLE_RULE_ID_PREFIXES.QUICK
];

const IPV4_PATTERN = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV4_HOST_PREFIX_LENGTH = 32;
const IPV6_HOST_PREFIX_LENGTH = 128;

/** What the Unblock flow needs to know about one blocked record. */
export interface UnblockTarget {
  processName: string;
  processPath?: string;
  /** Domain when known, else the IP address. */
  destination: string;
  targetPort: number;
  protocol: TransportProtocol;
  blockReason?: BlockReason;
  matchedRuleId?: string;
  proxyId?: string;
}

export type UnblockRoute = 'direct' | 'proxy';

export type UnblockOptionKind =
  | 'changeRule'
  | 'exceptionApp'
  | 'exceptionSite'
  | 'exceptionAppSite'
  | 'disableRule'
  | 'cannotOutrank'
  | 'testProxy'
  | 'openProxy'
  | 'pause'
  | 'flushDns'
  | 'restartApp';

/** Actions that are not a rule change: the screen runs them with its existing handlers. */
export type UnblockCommand = 'testProxy' | 'openProxy' | 'pause' | 'flushDns' | 'none';

export type UnblockRisk = 'normal' | 'impact' | 'unprotected';

export interface UnblockOption {
  id: string;
  kind: UnblockOptionKind;
  route: UnblockRoute;
  titleKey: string;
  descKey: string;
  params: Record<string, string>;
  risk: UnblockRisk;
  /** True when the option can be limited in time (exceptions only). */
  supportsDuration: boolean;
  /** Set for options that run an action instead of changing rules. */
  command?: UnblockCommand;
}

export interface UnblockContext {
  rules: RoutingRule[];
  proxies: ProxyNode[];
  chains: ProxyChain[];
  t: Translate;
  /** Current time in epoch milliseconds (a parameter so tests are deterministic). */
  now?: number;
}

/**
 * A set of rule changes and their exact inverse. It deliberately has no field for security
 * settings: no plan can ever switch the kill switch off.
 */
export interface UnblockPlan {
  upserts: RoutingRule[];
  removeIds: string[];
  undoUpserts: RoutingRule[];
  undoRemoveIds: string[];
  expiresAt: string | null;
}

/** Locale keys of every option; spelled out so they stay greppable. */
const OPTION_KEYS: Record<string, { title: string; desc: string }> = {
  'changeRule:direct': {
    title: 'unblock.option.change_rule_direct.title',
    desc: 'unblock.option.change_rule_direct.desc'
  },
  'changeRule:proxy': {
    title: 'unblock.option.change_rule_proxy.title',
    desc: 'unblock.option.change_rule_proxy.desc'
  },
  'exceptionApp:direct': {
    title: 'unblock.option.exception_app_direct.title',
    desc: 'unblock.option.exception_app_direct.desc'
  },
  'exceptionApp:proxy': {
    title: 'unblock.option.exception_app_proxy.title',
    desc: 'unblock.option.exception_app_proxy.desc'
  },
  'exceptionSite:direct': {
    title: 'unblock.option.exception_site_direct.title',
    desc: 'unblock.option.exception_site_direct.desc'
  },
  'exceptionSite:proxy': {
    title: 'unblock.option.exception_site_proxy.title',
    desc: 'unblock.option.exception_site_proxy.desc'
  },
  'exceptionAppSite:direct': {
    title: 'unblock.option.exception_app_site_direct.title',
    desc: 'unblock.option.exception_app_site_direct.desc'
  },
  'cannotOutrank:direct': {
    title: 'unblock.option.cannot_outrank.title',
    desc: 'unblock.option.cannot_outrank.desc'
  },
  'disableRule:direct': {
    title: 'unblock.option.disable_rule.title',
    desc: 'unblock.option.disable_rule.desc'
  },
  'appDirectUnprotected:direct': {
    title: 'unblock.option.app_direct_unprotected.title',
    desc: 'unblock.option.app_direct_unprotected.desc'
  },
  'testProxy:direct': {
    title: 'unblock.option.test_proxy.title',
    desc: 'unblock.option.test_proxy.desc'
  },
  'openProxy:direct': {
    title: 'unblock.option.open_proxy.title',
    desc: 'unblock.option.open_proxy.desc'
  },
  'pause:direct': {
    title: 'unblock.option.pause.title',
    desc: 'unblock.option.pause.desc'
  },
  'flushDns:direct': {
    title: 'unblock.option.flush_dns.title',
    desc: 'unblock.option.flush_dns.desc'
  },
  'restartApp:direct': {
    title: 'unblock.option.restart_app.title',
    desc: 'unblock.option.restart_app.desc'
  }
};

/** Priority an exception needs to win against `blockingRule`: strictly lower number, at most 6. */
export function exceptionPriority(blockingRule?: RoutingRule | null): number {
  if (!blockingRule) {
    return UI_CONFIG.TROUBLESHOOT_RULE_PRIORITY;
  }
  return Math.max(
    0,
    Math.min(UI_CONFIG.TROUBLESHOOT_RULE_PRIORITY, blockingRule.priority - 1)
  );
}

/** Expiry instant of a duration, or null for "always". */
export function resolveExpiry(duration: UnblockDuration, now: number): string | null {
  if (duration === 'always') {
    return null;
  }
  return new Date(now + DURATION_MS[duration]).toISOString();
}

function findBlockingRule(
  target: UnblockTarget,
  rules: RoutingRule[]
): RoutingRule | null {
  if (!target.matchedRuleId) {
    return null;
  }
  return rules.find((r) => r.id === target.matchedRuleId) ?? null;
}

/** True when a Simple screen created the rule, so it can be retargeted in place. */
export function isInPlaceRule(rule: RoutingRule | null): boolean {
  return (
    rule !== null &&
    rule.action.type === 'block' &&
    IN_PLACE_RULE_PREFIXES.some((prefix) => rule.id.startsWith(prefix))
  );
}

/**
 * True when no exception can win against the blocking rule: a rule at priority 0 (or below)
 * cannot be outranked, and a tie would lose on declared order.
 */
export function cannotOutrankRule(blockingRule: RoutingRule | null): boolean {
  return blockingRule !== null && blockingRule.priority <= 0;
}

function isIpAddress(value: string): boolean {
  return IPV4_PATTERN.test(value) || value.includes(':');
}

function makeOption(
  kind: UnblockOptionKind,
  route: UnblockRoute,
  extra: Partial<UnblockOption> & { params?: Record<string, string> } = {}
): UnblockOption {
  const lookupKind = kind === 'exceptionApp' && extra.risk === 'unprotected'
    ? 'appDirectUnprotected'
    : kind;
  const keys = OPTION_KEYS[`${lookupKind}:${route}`];
  return {
    id: `${kind}:${route}:${extra.risk ?? 'normal'}`,
    kind,
    route,
    titleKey: keys.title,
    descKey: keys.desc,
    params: extra.params ?? {},
    risk: extra.risk ?? 'normal',
    supportsDuration: extra.supportsDuration ?? false,
    command: extra.command
  };
}

function commandOption(fix: BlockFix): UnblockOption | null {
  switch (fix) {
    case 'testProxy':
      return makeOption('testProxy', 'direct', { command: 'testProxy' });
    case 'openProxy':
      return makeOption('openProxy', 'direct', { command: 'openProxy' });
    case 'pause':
      return makeOption('pause', 'direct', {
        command: 'pause',
        risk: 'unprotected',
        params: { minutes: String(UI_CONFIG.OUTAGE_PAUSE_MINUTES) }
      });
    case 'flushDns':
      return makeOption('flushDns', 'direct', { command: 'flushDns' });
    case 'restartApp':
      return makeOption('restartApp', 'direct', { command: 'none' });
    default:
      return null;
  }
}

/**
 * Lists what can be done about one block, most useful first. Records whose reason is only
 * explained (QUIC, private DNS, unknown program) get no option at all.
 */
export function listUnblockOptions(
  target: UnblockTarget,
  ctx: UnblockContext
): UnblockOption[] {
  const info = describeBlockReason(target.blockReason);
  const blockingRule = findBlockingRule(target, ctx.rules);
  const proxyAvailable = resolveSimpleProxyAction(ctx.proxies, ctx.chains) !== null;
  const options: UnblockOption[] = [];

  for (const fix of info.fixes) {
    switch (fix) {
      case 'changeRule': {
        if (isInPlaceRule(blockingRule)) {
          options.push(makeOption('changeRule', 'direct'));
          if (proxyAvailable) {
            options.push(makeOption('changeRule', 'proxy'));
          }
        }
        break;
      }
      case 'exception': {
        if (cannotOutrankRule(blockingRule)) {
          options.push(makeOption('cannotOutrank', 'direct', { command: 'none' }));
          break;
        }
        options.push(
          makeOption('exceptionAppSite', 'direct', { supportsDuration: true }),
          makeOption('exceptionApp', 'direct', { supportsDuration: true }),
          makeOption('exceptionSite', 'direct', { supportsDuration: true })
        );
        if (info.reason === 'defaultPolicyBlock' && proxyAvailable) {
          options.push(
            makeOption('exceptionApp', 'proxy', { supportsDuration: true }),
            makeOption('exceptionSite', 'proxy', { supportsDuration: true })
          );
        }
        break;
      }
      case 'disableRule': {
        if (blockingRule && !isInPlaceRule(blockingRule)) {
          options.push(
            makeOption('disableRule', 'direct', {
              risk: 'impact',
              params: { rule: blockingRule.name }
            })
          );
        }
        break;
      }
      case 'appDirect': {
        if (cannotOutrankRule(blockingRule)) {
          if (!options.some((o) => o.kind === 'cannotOutrank')) {
            options.push(makeOption('cannotOutrank', 'direct', { command: 'none' }));
          }
          break;
        }
        options.push(
          makeOption('exceptionApp', 'direct', {
            risk: 'unprotected',
            supportsDuration: true
          })
        );
        break;
      }
      default: {
        const command = commandOption(fix);
        if (command) {
          options.push(command);
        }
      }
    }
  }
  return options;
}

function exceptionAction(
  route: UnblockRoute,
  ctx: UnblockContext
): RuleAction | null {
  if (route === 'direct') {
    return { type: 'direct' };
  }
  return resolveSimpleProxyAction(ctx.proxies, ctx.chains);
}

function buildException(
  target: UnblockTarget,
  option: UnblockOption,
  priority: number,
  action: RuleAction,
  temporary: boolean,
  ctx: UnblockContext
): RoutingRule {
  const appName = getFriendlyAppName(target.processName).displayName;
  const appSlug = slugifyRuleKey(target.processName);
  const siteSlug = slugifyRuleKey(target.destination);
  const withApp = option.kind === 'exceptionApp' || option.kind === 'exceptionAppSite';
  const withSite = option.kind === 'exceptionSite' || option.kind === 'exceptionAppSite';
  const destinationIsIp = isIpAddress(target.destination);
  const ipCidrs =
    withSite && destinationIsIp
      ? [
          `${target.destination}/${
            target.destination.includes(':')
              ? IPV6_HOST_PREFIX_LENGTH
              : IPV4_HOST_PREFIX_LENGTH
          }`
        ]
      : [];
  const nameKey = nameKeyFor(option);
  let id: string;
  if (option.kind === 'exceptionApp') {
    id = `${UI_CONFIG.UNBLOCK_RULE_ID_PREFIXES.APP}${appSlug}`;
  } else if (option.kind === 'exceptionSite') {
    id = `${UI_CONFIG.UNBLOCK_RULE_ID_PREFIXES.SITE}${siteSlug}`;
  } else {
    id = `${UI_CONFIG.UNBLOCK_RULE_ID_PREFIXES.APP}${appSlug}-site-${siteSlug}`;
  }
  // A proxy exception never replaces a direct one, and a temporary one never replaces a
  // permanent one: each variant has its own id.
  if (option.route === 'proxy') {
    id += UI_CONFIG.UNBLOCK_RULE_ID_SUFFIXES.PROXY;
  }
  if (temporary) {
    id += UI_CONFIG.UNBLOCK_RULE_ID_SUFFIXES.TEMPORARY;
  }
  return {
    id,
    name: ctx.t(nameKey, { name: withApp ? appName : target.destination, site: target.destination, app: appName }),
    enabled: true,
    priority,
    processPatterns: withApp ? [target.processName] : [],
    domainPatterns: withSite && !destinationIsIp ? [target.destination] : [],
    ipCidrs,
    portRanges: [],
    protocol: 'any',
    action
  };
}

function nameKeyFor(option: UnblockOption): string {
  if (option.kind === 'exceptionAppSite') {
    return 'unblock.rules.app_site_direct';
  }
  const via = option.route === 'proxy' ? 'proxy' : 'direct';
  return option.kind === 'exceptionApp'
    ? via === 'proxy'
      ? 'unblock.rules.app_proxy'
      : 'troubleshoot.rules.app_direct'
    : via === 'proxy'
      ? 'unblock.rules.site_proxy'
      : 'troubleshoot.rules.site_direct';
}

/**
 * Builds the rule changes of one option and their inverse. Returns null for options that are
 * not rule changes, or when a proxy route was chosen but no proxy exists.
 */
export function buildUnblockPlan(
  target: UnblockTarget,
  option: UnblockOption,
  duration: UnblockDuration,
  ctx: UnblockContext
): UnblockPlan | null {
  if (option.command) {
    return null;
  }
  const now = ctx.now ?? Date.now();
  const blockingRule = findBlockingRule(target, ctx.rules);
  let upsert: RoutingRule | null = null;
  let expiresAt: string | null = null;

  if (option.kind === 'changeRule') {
    const action = exceptionAction(option.route, ctx);
    if (!blockingRule || !isInPlaceRule(blockingRule) || !action) {
      return null;
    }
    upsert = { ...blockingRule, action };
  } else if (option.kind === 'disableRule') {
    if (!blockingRule) {
      return null;
    }
    upsert = { ...blockingRule, enabled: false };
  } else {
    const action = exceptionAction(option.route, ctx);
    if (!action || cannotOutrankRule(blockingRule)) {
      return null;
    }
    expiresAt = option.supportsDuration ? resolveExpiry(duration, now) : null;
    upsert = buildException(
      target,
      option,
      exceptionPriority(blockingRule),
      action,
      expiresAt !== null,
      ctx
    );
    if (expiresAt) {
      upsert.expiresAt = expiresAt;
    }
  }

  const previous = ctx.rules.find((r) => r.id === upsert.id) ?? null;
  return {
    upserts: [upsert],
    removeIds: [],
    undoUpserts: previous ? [previous] : [],
    undoRemoveIds: previous ? [] : [upsert.id],
    expiresAt
  };
}

/** The request the daemon predicts the outcome of, for the preview before confirming. */
export function buildPreviewRequest(target: UnblockTarget): ConnectionRequest {
  return {
    processName: target.processName,
    processPath: target.processPath,
    targetHost: target.destination,
    targetPort: target.targetPort,
    protocol: target.protocol
  };
}

function patternsOverlap(a: string[], b: string[]): boolean {
  if (a.length === 0 || b.length === 0) {
    return true;
  }
  const lowered = new Set(a.map((p) => p.toLowerCase()));
  return (
    b.some((p) => lowered.has(p.toLowerCase())) ||
    a.some((p) => p.includes('*')) ||
    b.some((p) => p.includes('*'))
  );
}

/**
 * The user's enabled proxy rules (Simple app/site rules and any other rule that sends traffic to
 * a proxy or chain) that a direct exception of the plan would outrank for other traffic of the
 * same app or site. Equal priority counts: a tie is decided by declared order.
 */
export function findOutrankedProxyRules(
  plan: UnblockPlan,
  existingRules: RoutingRule[]
): RoutingRule[] {
  const outranked = new Map<string, RoutingRule>();
  for (const exception of plan.upserts) {
    if (
      !exception.id.startsWith('rule-unblock-') ||
      !exception.enabled ||
      exception.action.type !== 'direct'
    ) {
      continue;
    }
    for (const rule of existingRules) {
      if (
        rule.id === exception.id ||
        !rule.enabled ||
        (rule.action.type !== 'proxy' && rule.action.type !== 'chain') ||
        rule.priority < exception.priority ||
        !patternsOverlap(exception.processPatterns, rule.processPatterns) ||
        !patternsOverlap(
          [...exception.domainPatterns, ...exception.ipCidrs],
          [...rule.domainPatterns, ...rule.ipCidrs]
        )
      ) {
        continue;
      }
      outranked.set(rule.id, rule);
    }
  }
  return Array.from(outranked.values());
}

/** One plain-language line per rule change, for the confirmation dialog. */
export function describePlanChanges(
  plan: UnblockPlan,
  existingRules: RoutingRule[],
  t: Translate
): string[] {
  const lines: string[] = [];
  for (const rule of plan.upserts) {
    const existing = existingRules.find((r) => r.id === rule.id);
    if (!existing) {
      lines.push(t('unblock.diff.added', { name: rule.name }));
    } else if (existing.enabled && !rule.enabled) {
      lines.push(t('unblock.diff.disabled', { name: rule.name }));
    } else {
      lines.push(t('unblock.diff.changed', { name: rule.name }));
    }
    if (rule.expiresAt) {
      lines.push(
        t('unblock.diff.expires', {
          time: new Intl.DateTimeFormat(undefined, { timeStyle: 'short' }).format(
            new Date(rule.expiresAt)
          )
        })
      );
    }
  }
  for (const id of plan.removeIds) {
    const existing = existingRules.find((r) => r.id === id);
    lines.push(t('unblock.diff.removed', { name: existing?.name ?? id }));
  }
  const outranked = findOutrankedProxyRules(plan, existingRules);
  if (outranked.length > 0) {
    lines.push(
      t('unblock.diff.outranks', { names: outranked.map((r) => r.name).join(', ') })
    );
  }
  return lines;
}
