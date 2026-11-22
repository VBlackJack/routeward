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

import { describe, expect, it } from 'vitest';
import { UI_CONFIG } from '../config/constants';
import { BlockReason, ProxyNode, RoutingRule } from '../types/routeward';
import { KNOWN_BLOCK_REASONS } from './blockReason';
import {
  buildPreviewRequest,
  buildUnblockPlan,
  describePlanChanges,
  exceptionPriority,
  findOutrankedProxyRules,
  listUnblockOptions,
  UNBLOCK_DURATIONS,
  UnblockContext,
  UnblockOption,
  UnblockTarget
} from './unblockPlan';

const NOW = Date.UTC(2026, 10, 22, 10, 0, 0);

const t = (key: string, options?: Record<string, unknown>) =>
  options ? `${key}|${JSON.stringify(options)}` : key;

function rule(partial: Partial<RoutingRule> & { id: string }): RoutingRule {
  return {
    name: partial.id,
    enabled: true,
    priority: 50,
    processPatterns: [],
    domainPatterns: [],
    ipCidrs: [],
    portRanges: [],
    protocol: 'any',
    action: { type: 'block' },
    ...partial
  };
}

const proxy: ProxyNode = {
  id: 'p1',
  name: 'Office proxy',
  protocol: 'socks5',
  host: '10.0.0.2',
  port: 1080,
  auth: null,
  udpEnabled: true,
  tls: false,
  sni: null,
  enabled: true,
  lastLatencyMs: null,
  exitIp: null
};

function ctx(rules: RoutingRule[], proxies: ProxyNode[] = [proxy]): UnblockContext {
  return { rules, proxies, chains: [], t, now: NOW };
}

function target(partial: Partial<UnblockTarget> = {}): UnblockTarget {
  return {
    processName: 'chrome.exe',
    destination: 'example.com',
    targetPort: 443,
    protocol: 'tcp',
    blockReason: 'ruleBlock',
    ...partial
  };
}

function findOption(
  options: UnblockOption[],
  kind: UnblockOption['kind'],
  route: UnblockOption['route'] = 'direct'
): UnblockOption {
  const found = options.find((o) => o.kind === kind && o.route === route);
  if (!found) {
    throw new Error(`option ${kind}/${route} missing`);
  }
  return found;
}

describe('exceptionPriority', () => {
  it('uses min(6, blocking priority - 1)', () => {
    expect(exceptionPriority(rule({ id: 'b', priority: 3 }))).toBe(2);
    expect(exceptionPriority(rule({ id: 'b', priority: 100 }))).toBe(
      UI_CONFIG.TROUBLESHOOT_RULE_PRIORITY
    );
  });

  it('never ties with the blocking rule, which would lose on declared order', () => {
    expect(exceptionPriority(rule({ id: 'b', priority: 6 }))).toBe(5);
    expect(exceptionPriority(rule({ id: 'b', priority: 7 }))).toBe(6);
  });

  it('clamps at zero and defaults to the troubleshoot priority without a rule', () => {
    expect(exceptionPriority(rule({ id: 'b', priority: 0 }))).toBe(0);
    expect(exceptionPriority(null)).toBe(UI_CONFIG.TROUBLESHOOT_RULE_PRIORITY);
  });
});

describe('unblock plans for a rule block', () => {
  const pack = rule({ id: 'rule-pack-ads', priority: 3, name: 'Ads pack' });
  const rules = [pack];
  const blocked = target({ matchedRuleId: 'rule-pack-ads' });

  it('creates an app exception above a priority 3 blocking rule', () => {
    const options = listUnblockOptions(blocked, ctx(rules));
    const plan = buildUnblockPlan(
      blocked,
      findOption(options, 'exceptionApp'),
      'always',
      ctx(rules)
    );
    expect(plan?.upserts).toHaveLength(1);
    const created = plan!.upserts[0];
    expect(created.priority).toBe(2);
    expect(created.id).toBe('rule-unblock-app-chrome-exe');
    expect(created.processPatterns).toEqual(['chrome.exe']);
    expect(created.action).toEqual({ type: 'direct' });
    expect(created.expiresAt).toBeUndefined();
  });

  it('creates a site exception with the site id prefix', () => {
    const options = listUnblockOptions(blocked, ctx(rules));
    const plan = buildUnblockPlan(
      blocked,
      findOption(options, 'exceptionSite'),
      'always',
      ctx(rules)
    );
    expect(plan!.upserts[0].id).toBe('rule-unblock-site-example-com');
    expect(plan!.upserts[0].domainPatterns).toEqual(['example.com']);
    expect(plan!.upserts[0].processPatterns).toEqual([]);
  });

  it('targets an IP destination with a host CIDR instead of a domain pattern', () => {
    const ipTarget = target({ destination: '203.0.113.9', matchedRuleId: 'rule-pack-ads' });
    const options = listUnblockOptions(ipTarget, ctx(rules));
    const plan = buildUnblockPlan(
      ipTarget,
      findOption(options, 'exceptionSite'),
      'always',
      ctx(rules)
    );
    expect(plan!.upserts[0].ipCidrs).toEqual(['203.0.113.9/32']);
    expect(plan!.upserts[0].domainPatterns).toEqual([]);
  });

  it('offers turning the rule off as a secondary option that disables only that rule', () => {
    const options = listUnblockOptions(blocked, ctx(rules));
    const disable = findOption(options, 'disableRule');
    expect(disable.risk).toBe('impact');
    const plan = buildUnblockPlan(blocked, disable, 'always', ctx(rules));
    expect(plan!.upserts).toEqual([{ ...pack, enabled: false }]);
    expect(plan!.undoUpserts).toEqual([pack]);
  });

  it('sets expiresAt for 15 minutes and 1 hour and none for always', () => {
    const options = listUnblockOptions(blocked, ctx(rules));
    const option = findOption(options, 'exceptionApp');
    const short = buildUnblockPlan(blocked, option, 'minutes15', ctx(rules));
    const long = buildUnblockPlan(blocked, option, 'hour1', ctx(rules));
    const always = buildUnblockPlan(blocked, option, 'always', ctx(rules));
    expect(short!.upserts[0].expiresAt).toBe(
      new Date(NOW + UI_CONFIG.UNBLOCK_SHORT_DURATION_MS).toISOString()
    );
    expect(long!.upserts[0].expiresAt).toBe(
      new Date(NOW + UI_CONFIG.UNBLOCK_LONG_DURATION_MS).toISOString()
    );
    expect(always!.upserts[0].expiresAt).toBeUndefined();
    expect(always!.expiresAt).toBeNull();
  });

  it('undo removes a created exception and restores a replaced one', () => {
    const options = listUnblockOptions(blocked, ctx(rules));
    const option = findOption(options, 'exceptionApp');
    const fresh = buildUnblockPlan(blocked, option, 'always', ctx(rules));
    expect(fresh!.undoRemoveIds).toEqual(['rule-unblock-app-chrome-exe']);
    expect(fresh!.undoUpserts).toEqual([]);

    const previous = rule({
      id: 'rule-unblock-app-chrome-exe',
      priority: 6,
      action: { type: 'direct' }
    });
    const replaced = buildUnblockPlan(blocked, option, 'always', ctx([...rules, previous]));
    expect(replaced!.undoUpserts).toEqual([previous]);
    expect(replaced!.undoRemoveIds).toEqual([]);
  });
});

describe('Simple rules are changed in place', () => {
  const simple = rule({
    id: 'rule-app-chrome-exe',
    priority: 15,
    processPatterns: ['chrome.exe'],
    action: { type: 'block' }
  });
  const blocked = target({ matchedRuleId: simple.id });

  it('rewrites the Simple rule to Direct and keeps everything else', () => {
    const options = listUnblockOptions(blocked, ctx([simple]));
    const plan = buildUnblockPlan(
      blocked,
      findOption(options, 'changeRule'),
      'always',
      ctx([simple])
    );
    expect(plan!.upserts).toEqual([{ ...simple, action: { type: 'direct' } }]);
    expect(plan!.undoUpserts).toEqual([simple]);
    expect(plan!.removeIds).toEqual([]);
  });

  it('offers the proxy variant only when a proxy exists', () => {
    const withProxy = listUnblockOptions(blocked, ctx([simple]));
    expect(withProxy.some((o) => o.kind === 'changeRule' && o.route === 'proxy')).toBe(true);
    const withoutProxy = listUnblockOptions(blocked, ctx([simple], []));
    expect(withoutProxy.some((o) => o.kind === 'changeRule' && o.route === 'proxy')).toBe(false);
  });

  it('does not offer to turn a Simple rule off, only to change it or add an exception', () => {
    const options = listUnblockOptions(blocked, ctx([simple]));
    expect(options.some((o) => o.kind === 'disableRule')).toBe(false);
    expect(options.some((o) => o.kind === 'exceptionApp')).toBe(true);
  });

  it('treats a Simple rule with a non-block action as not changeable in place', () => {
    const proxied = { ...simple, action: { type: 'proxy' as const, targetId: 'p1' } };
    const options = listUnblockOptions(blocked, ctx([proxied]));
    expect(options.some((o) => o.kind === 'changeRule')).toBe(false);
  });
});

describe('unblock options by reason', () => {
  it('offers a direct or proxy exception for the default policy', () => {
    const options = listUnblockOptions(target({ blockReason: 'defaultPolicyBlock' }), ctx([]));
    const plan = buildUnblockPlan(
      target({ blockReason: 'defaultPolicyBlock' }),
      findOption(options, 'exceptionApp', 'proxy'),
      'always',
      ctx([])
    );
    expect(plan!.upserts[0].action.type).toBe('proxy');
    expect(plan!.upserts[0].priority).toBe(UI_CONFIG.TROUBLESHOOT_RULE_PRIORITY);
  });

  it('offers test, open, unprotected app exception and pause for a proxy outage', () => {
    const outage = target({ blockReason: 'killSwitchProxyUnreachable' });
    const options = listUnblockOptions(outage, ctx([]));
    expect(options.map((o) => o.kind)).toEqual([
      'testProxy',
      'openProxy',
      'exceptionApp',
      'pause'
    ]);
    const unprotected = options.find((o) => o.risk === 'unprotected');
    expect(unprotected?.supportsDuration).toBe(true);
  });

  it('flags the pause option as risky, like the unprotected exception', () => {
    const outage = target({ blockReason: 'killSwitchProxyUnreachable' });
    const pause = listUnblockOptions(outage, ctx([])).find((o) => o.kind === 'pause');
    expect(pause?.risk).toBe('unprotected');
  });

  it('only opens the proxy for rejected credentials and misconfiguration', () => {
    const auth = listUnblockOptions(
      target({ blockReason: 'killSwitchProxyAuthRejected' }),
      ctx([])
    );
    expect(auth.map((o) => o.kind)).toEqual(['openProxy', 'testProxy']);
    const misconfigured = listUnblockOptions(
      target({ blockReason: 'killSwitchProxyMisconfigured' }),
      ctx([])
    );
    expect(misconfigured.map((o) => o.kind)).toEqual(['openProxy']);
  });

  it('explains without options for QUIC, encrypted DNS, unknown programs and local names', () => {
    for (const reason of [
      'quicBlocked',
      'encryptedDnsBlocked',
      'unknownProcessPolicy',
      'unknownProcessKillSwitch',
      'localNameGuard'
    ] as BlockReason[]) {
      expect(listUnblockOptions(target({ blockReason: reason }), ctx([]))).toEqual([]);
    }
  });

  it('offers flush DNS and a restart hint for the Fake-IP guard', () => {
    const options = listUnblockOptions(target({ blockReason: 'fakeIpEgressGuard' }), ctx([]));
    expect(options.map((o) => o.command)).toEqual(['flushDns', 'none']);
  });

  it('offers an app direct exception or the proxy settings for UDP limits', () => {
    for (const reason of ['fragmentedUdpBlocked', 'udpProxyUnsupported'] as BlockReason[]) {
      const options = listUnblockOptions(target({ blockReason: reason }), ctx([]));
      expect(options.map((o) => o.kind)).toEqual(['exceptionApp', 'openProxy']);
    }
  });

  it('exception priority follows the matched rule of a kill switch block', () => {
    const matched = rule({ id: 'rule-app-x', priority: 4, action: { type: 'proxy', targetId: 'p1' } });
    const outage = target({ blockReason: 'killSwitchProxyTimeout', matchedRuleId: 'rule-app-x' });
    const options = listUnblockOptions(outage, ctx([matched]));
    const plan = buildUnblockPlan(
      outage,
      options.find((o) => o.risk === 'unprotected')!,
      'always',
      ctx([matched])
    );
    expect(plan!.upserts[0].priority).toBe(3);
  });
});

describe('safety of every plan', () => {
  it('never produces anything but rule changes, and never touches the kill switch', () => {
    const blockingRule = rule({ id: 'rule-pack-x', priority: 9 });
    const simple = rule({ id: 'rule-app-chrome-exe', priority: 15 });
    for (const reason of [...KNOWN_BLOCK_REASONS, 'unknown' as BlockReason]) {
      for (const matchedRuleId of ['rule-pack-x', 'rule-app-chrome-exe', undefined]) {
        const subject = target({ blockReason: reason, matchedRuleId });
        const context = ctx([blockingRule, simple]);
        for (const option of listUnblockOptions(subject, context)) {
          for (const duration of UNBLOCK_DURATIONS) {
            const plan = buildUnblockPlan(subject, option, duration, context);
            if (!plan) continue;
            expect(Object.keys(plan).sort()).toEqual([
              'expiresAt',
              'removeIds',
              'undoRemoveIds',
              'undoUpserts',
              'upserts'
            ]);
            expect(JSON.stringify(plan)).not.toMatch(/killSwitch|securityPolicy/);
            for (const upserted of plan.upserts.filter((r) =>
              r.id.startsWith('rule-unblock-')
            )) {
              expect(upserted.priority).toBeLessThanOrEqual(
                UI_CONFIG.TROUBLESHOOT_RULE_PRIORITY
              );
            }
          }
        }
      }
    }
  });

  it('returns no plan for command options', () => {
    const outage = target({ blockReason: 'killSwitchProxyTimeout' });
    const options = listUnblockOptions(outage, ctx([]));
    for (const option of options.filter((o) => o.command)) {
      expect(buildUnblockPlan(outage, option, 'always', ctx([]))).toBeNull();
    }
  });
});

describe('preview request and diff lines', () => {
  it('builds the connection request the daemon predicts', () => {
    expect(
      buildPreviewRequest(target({ processPath: 'C:/chrome.exe', targetPort: 8443 }))
    ).toEqual({
      processName: 'chrome.exe',
      processPath: 'C:/chrome.exe',
      targetHost: 'example.com',
      targetPort: 8443,
      protocol: 'tcp'
    });
  });

  it('describes added, changed and disabled rules plus the expiry', () => {
    const pack = rule({ id: 'rule-pack-ads', priority: 3, name: 'Ads pack' });
    const blocked = target({ matchedRuleId: 'rule-pack-ads' });
    const context = ctx([pack]);
    const options = listUnblockOptions(blocked, context);
    const added = buildUnblockPlan(blocked, findOption(options, 'exceptionApp'), 'hour1', context)!;
    const lines = describePlanChanges(added, [pack], t);
    expect(lines[0]).toMatch(/^unblock\.diff\.added/);
    expect(lines[1]).toMatch(/^unblock\.diff\.expires/);
    const disabled = buildUnblockPlan(blocked, findOption(options, 'disableRule'), 'always', context)!;
    expect(describePlanChanges(disabled, [pack], t)[0]).toMatch(/^unblock\.diff\.disabled/);
  });
});

describe('exception ids keep permanent, temporary, direct and proxy rules apart', () => {
  const pack = rule({ id: 'rule-pack-ads', priority: 3, name: 'Ads pack' });
  const blocked = target({ matchedRuleId: 'rule-pack-ads' });
  const permanentDirect = rule({
    id: 'rule-unblock-app-chrome-exe',
    priority: 2,
    action: { type: 'direct' },
    processPatterns: ['chrome.exe']
  });

  it('adds a separate -tmp rule instead of rewriting a permanent Direct exception', () => {
    const context = ctx([pack, permanentDirect]);
    const option = findOption(listUnblockOptions(blocked, context), 'exceptionApp');
    const plan = buildUnblockPlan(blocked, option, 'minutes15', context)!;
    expect(plan.upserts).toHaveLength(1);
    expect(plan.upserts[0].id).toBe('rule-unblock-app-chrome-exe-tmp');
    expect(plan.upserts[0].expiresAt).toBeTruthy();
    expect(plan.removeIds).toEqual([]);
    expect(plan.undoRemoveIds).toEqual(['rule-unblock-app-chrome-exe-tmp']);
    expect(plan.undoUpserts).toEqual([]);
  });

  it('keeps the plain id for a permanent exception, and -tmp for a site exception too', () => {
    const context = ctx([pack]);
    const options = listUnblockOptions(blocked, context);
    const permanent = buildUnblockPlan(blocked, findOption(options, 'exceptionApp'), 'always', context)!;
    expect(permanent.upserts[0].id).toBe('rule-unblock-app-chrome-exe');
    const site = buildUnblockPlan(blocked, findOption(options, 'exceptionSite'), 'hour1', context)!;
    expect(site.upserts[0].id).toBe('rule-unblock-site-example-com-tmp');
  });

  it('a proxy exception does not replace a direct one', () => {
    const noRule = target({ blockReason: 'defaultPolicyBlock' });
    const context = ctx([permanentDirect]);
    const options = listUnblockOptions(noRule, context);
    const proxyPlan = buildUnblockPlan(
      noRule,
      findOption(options, 'exceptionApp', 'proxy'),
      'always',
      context
    )!;
    expect(proxyPlan.upserts[0].id).toBe('rule-unblock-app-chrome-exe-proxy');
    expect(proxyPlan.upserts[0].action.type).toBe('proxy');
    expect(proxyPlan.undoRemoveIds).toEqual(['rule-unblock-app-chrome-exe-proxy']);
    const tmpProxy = buildUnblockPlan(
      noRule,
      findOption(options, 'exceptionApp', 'proxy'),
      'hour1',
      context
    )!;
    expect(tmpProxy.upserts[0].id).toBe('rule-unblock-app-chrome-exe-proxy-tmp');
  });
});

describe('a blocking rule that cannot be outranked', () => {
  const top = rule({ id: 'rule-pack-top', priority: 0, name: 'Top pack' });
  const blocked = target({ matchedRuleId: 'rule-pack-top' });

  it('offers no exception, only the explanation and turning the rule off', () => {
    const options = listUnblockOptions(blocked, ctx([top]));
    expect(options.some((o) => o.kind.startsWith('exception'))).toBe(false);
    const cannot = options.find((o) => o.kind === 'cannotOutrank');
    expect(cannot?.command).toBe('none');
    expect(options.some((o) => o.kind === 'disableRule')).toBe(true);
    expect(buildUnblockPlan(blocked, cannot!, 'always', ctx([top]))).toBeNull();
  });

  it('also stops the unprotected exception of a proxy outage', () => {
    const outage = target({ blockReason: 'killSwitchProxyTimeout', matchedRuleId: 'rule-pack-top' });
    const options = listUnblockOptions(outage, ctx([top]));
    expect(options.some((o) => o.kind === 'exceptionApp')).toBe(false);
    expect(options.some((o) => o.kind === 'cannotOutrank')).toBe(true);
  });

  it('puts the app and site exception first, then app, then site', () => {
    const pack = rule({ id: 'rule-pack-ads', priority: 3 });
    const kinds = listUnblockOptions(target({ matchedRuleId: 'rule-pack-ads' }), ctx([pack]))
      .filter((o) => o.kind.startsWith('exception'))
      .map((o) => o.kind);
    expect(kinds).toEqual(['exceptionAppSite', 'exceptionApp', 'exceptionSite']);
  });
});

describe('proxy rules an exception would outrank', () => {
  const pack = rule({ id: 'rule-pack-ads', priority: 3, name: 'Ads pack' });
  const blocked = target({ matchedRuleId: 'rule-pack-ads' });
  const siteViaProxy = rule({
    id: 'rule-site-example-com',
    name: 'Example via proxy',
    priority: 20,
    domainPatterns: ['example.com'],
    action: { type: 'proxy', targetId: 'p1' }
  });
  const appViaProxy = rule({
    id: 'rule-app-chrome-exe',
    name: 'Chrome via proxy',
    priority: 15,
    processPatterns: ['chrome.exe'],
    action: { type: 'proxy', targetId: 'p1' }
  });
  const otherApp = rule({
    id: 'rule-app-firefox-exe',
    priority: 15,
    processPatterns: ['firefox.exe'],
    action: { type: 'proxy', targetId: 'p1' }
  });
  const stronger = rule({
    id: 'rule-expert-first',
    priority: 1,
    action: { type: 'proxy', targetId: 'p1' }
  });
  const expert = rule({
    id: 'rule-expert-proxy',
    name: 'Expert proxy',
    priority: 40,
    action: { type: 'chain', targetId: 'c1' }
  });

  it('lists Simple app and site rules and other proxy rules, not unrelated or stronger ones', () => {
    const context = ctx([pack, siteViaProxy, appViaProxy, otherApp, stronger, expert]);
    const option = findOption(listUnblockOptions(blocked, context), 'exceptionApp');
    const plan = buildUnblockPlan(blocked, option, 'always', context)!;
    const ids = findOutrankedProxyRules(plan, context.rules).map((r) => r.id).sort();
    expect(ids).toEqual(['rule-app-chrome-exe', 'rule-expert-proxy', 'rule-site-example-com']);
  });

  it('puts them in the confirmation lines', () => {
    const context = ctx([pack, appViaProxy]);
    const option = findOption(listUnblockOptions(blocked, context), 'exceptionApp');
    const plan = buildUnblockPlan(blocked, option, 'always', context)!;
    const lines = describePlanChanges(plan, context.rules, t);
    expect(lines.some((l) => l.startsWith('unblock.diff.outranks') && l.includes('Chrome via proxy'))).toBe(true);
  });

  it('says nothing for a proxy exception or when no proxy rule exists', () => {
    const noRule = target({ blockReason: 'defaultPolicyBlock' });
    const context = ctx([appViaProxy]);
    const proxyPlan = buildUnblockPlan(
      noRule,
      findOption(listUnblockOptions(noRule, context), 'exceptionApp', 'proxy'),
      'always',
      context
    )!;
    expect(findOutrankedProxyRules(proxyPlan, context.rules)).toEqual([]);
    const bare = ctx([pack]);
    const plan = buildUnblockPlan(
      blocked,
      findOption(listUnblockOptions(blocked, bare), 'exceptionApp'),
      'always',
      bare
    )!;
    expect(findOutrankedProxyRules(plan, bare.rules)).toEqual([]);
  });
});
