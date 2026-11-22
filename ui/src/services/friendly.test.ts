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
import { ProxyChain, ProxyNode, RoutingRule } from '../types/routeward';
import {
  applyProxyRemovalToRule,
  buildSimpleAppRule,
  findShadowingRule,
  getFriendlyAppName,
  getHumanErrorKey,
  isSimpleCreatedRuleId,
  localizeEngineRuleName,
  normalizeProxyImportText,
  parseLooseProxyLink,
  planProxyRemoval,
  resolveEffectiveAppRule,
  resolveSimpleProxyAction,
  resolveSimpleRuleId,
  splitHostAndPort
} from './friendly';

const sampleRule = (overrides: Partial<RoutingRule>): RoutingRule => ({
  id: 'r',
  name: 'r',
  enabled: true,
  priority: 50,
  processPatterns: [],
  domainPatterns: [],
  ipCidrs: [],
  portRanges: [],
  protocol: 'any',
  action: { type: 'direct' },
  ...overrides
});

const sampleProxy = (id: string, enabled = true): ProxyNode => ({
  id,
  name: id,
  protocol: 'socks5',
  host: 'proxy.example.com',
  port: 1080,
  auth: null,
  udpEnabled: true,
  tls: false,
  sni: null,
  enabled,
  lastLatencyMs: null,
  exitIp: null
});

describe('friendly beginner helpers', () => {
  it('resolves friendly app names while keeping unknown names untouched', () => {
    expect(getFriendlyAppName('msedge.exe')).toEqual({
      displayName: 'Microsoft Edge',
      technicalName: 'msedge.exe'
    });
    expect(getFriendlyAppName('custom-tool.exe')).toEqual({
      displayName: 'custom-tool.exe',
      technicalName: null
    });
  });

  it('maps technical error details to localized troubleshoot reason keys', () => {
    expect(getHumanErrorKey(undefined)).toBe(
      'troubleshoot.reasons.blocked_by_rule'
    );
    expect(getHumanErrorKey('Kill-switch blocked connection')).toBe(
      'troubleshoot.reasons.killswitch'
    );
    expect(getHumanErrorKey('SOCKS5 auth rejected (407)')).toBe(
      'troubleshoot.reasons.auth'
    );
    expect(getHumanErrorKey('TCP connect timed out')).toBe(
      'troubleshoot.reasons.timeout'
    );
    expect(getHumanErrorKey('UDP blocked on TCP-only proxy')).toBe(
      'troubleshoot.reasons.udp'
    );
  });

  it('routes Simple mode rules to active failover chain when enabled, otherwise primary proxy', () => {
    const p1 = sampleProxy('p1', true);
    const p2 = sampleProxy('p2', true);
    const failover: ProxyChain = {
      id: UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID,
      name: 'Backup',
      strategy: 'failover',
      proxyIds: ['p1', 'p2'],
      enabled: true
    };

    expect(resolveSimpleProxyAction([p1, p2], [failover])).toEqual({
      type: 'chain',
      targetId: UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID
    });
    expect(resolveSimpleProxyAction([p1, p2], [])).toEqual({
      type: 'proxy',
      targetId: 'p1'
    });
    expect(resolveSimpleProxyAction([sampleProxy('p1', false)], [failover])).toBeNull();
  });

  it('detects when a broad earlier rule shadows a site-specific rule with a different action', () => {
    const broadBrowser: RoutingRule = {
      id: 'r-browsers',
      name: 'Web Browsers',
      enabled: true,
      priority: 10,
      processPatterns: ['msedge.exe', 'firefox.exe'],
      domainPatterns: [],
      ipCidrs: [],
      portRanges: [],
      protocol: 'any',
      action: { type: 'proxy', targetId: 'p1' }
    };
    const siteDirect: RoutingRule = {
      id: 'r-bank',
      name: 'mybank.fr',
      enabled: true,
      priority: 50,
      processPatterns: [],
      domainPatterns: ['mybank.fr'],
      ipCidrs: [],
      portRanges: [],
      protocol: 'any',
      action: { type: 'direct' }
    };

    expect(findShadowingRule(siteDirect, [broadBrowser, siteDirect])?.id).toBe(
      'r-browsers'
    );
    expect(
      findShadowingRule({ ...siteDirect, priority: 8 }, [
        broadBrowser,
        { ...siteDirect, priority: 8 }
      ])
    ).toBeNull();
  });
});

describe('Simple rule identity and priority', () => {
  it('derives one deterministic id per application and per site', () => {
    expect(resolveSimpleRuleId([], ['Spotify.exe'], [])).toBe('rule-app-spotify-exe');
    expect(resolveSimpleRuleId([], [], ['*.exemple.com'])).toBe('rule-site-exemple-com');
    expect(isSimpleCreatedRuleId('rule-app-x')).toBe(true);
    expect(isSimpleCreatedRuleId('rule-quick-123')).toBe(true);
    expect(isSimpleCreatedRuleId('my-expert-rule')).toBe(false);
  });

  it('reuses the id of an older Simple rule with the same target so a repeat choice replaces it', () => {
    const legacy = sampleRule({
      id: 'rule-quick-abc',
      priority: 8,
      processPatterns: ['curl.exe']
    });
    expect(resolveSimpleRuleId([legacy], ['CURL.exe'], [])).toBe('rule-quick-abc');
    const expert = sampleRule({ id: 'expert-1', processPatterns: ['curl.exe'] });
    expect(resolveSimpleRuleId([expert], ['curl.exe'], [])).toBe('rule-app-curl-exe');
  });

  it('builds an application rule above the category cards with a friendly name', () => {
    const rule = buildSimpleAppRule({
      processName: 'spotify.exe',
      action: { type: 'block' }
    });
    expect(rule.id).toBe('rule-app-spotify-exe');
    expect(rule.name).toBe('Spotify');
    expect(rule.priority).toBe(UI_CONFIG.SIMPLE_APP_RULE_PRIORITY);
    expect(rule.priority).toBeLessThan(16);
  });

  it('finds the rule that really decides for an application, category rules included', () => {
    const category = sampleRule({
      id: 'rule-visual-app-browsers',
      priority: 18,
      processPatterns: ['firefox.exe', 'chrome*'],
      action: { type: 'direct' }
    });
    const own = sampleRule({
      id: 'rule-app-firefox-exe',
      priority: UI_CONFIG.SIMPLE_APP_RULE_PRIORITY,
      processPatterns: ['firefox.exe'],
      action: { type: 'block' }
    });
    expect(resolveEffectiveAppRule('firefox.exe', [category])?.id).toBe(category.id);
    expect(resolveEffectiveAppRule('firefox.exe', [category, own])?.id).toBe(own.id);
    expect(resolveEffectiveAppRule('chrome.exe', [category, own])?.id).toBe(category.id);
    expect(resolveEffectiveAppRule('vlc.exe', [category, own])).toBeNull();
    expect(
      resolveEffectiveAppRule('firefox.exe', [category, { ...own, enabled: false }])?.id
    ).toBe(category.id);
  });

  it('flags an application rule hidden behind a category rule', () => {
    const category = sampleRule({
      id: 'cat',
      priority: 10,
      processPatterns: ['firefox.exe', 'chrome.exe'],
      action: { type: 'direct' }
    });
    const own = sampleRule({
      id: 'own',
      priority: 15,
      processPatterns: ['Firefox.exe'],
      action: { type: 'block' }
    });
    expect(findShadowingRule(own, [category, own])?.id).toBe('cat');
    expect(
      findShadowingRule({ ...own, priority: 5 }, [category, { ...own, priority: 5 }])
    ).toBeNull();
    expect(
      findShadowingRule({ ...own, processPatterns: ['vlc.exe'] }, [
        category,
        { ...own, processPatterns: ['vlc.exe'] }
      ])
    ).toBeNull();
  });

  it('shows the engine fallback rule name through the localized label', () => {
    const t = (key: string) => `[${key}]`;
    expect(localizeEngineRuleName(UI_CONFIG.ENGINE_DEFAULT_RULE_NAME, t)).toBe(
      '[rules.generated.default_policy]'
    );
    expect(localizeEngineRuleName('Browsers', t)).toBe('Browsers');
  });

  it('never adopts an Expert failover chain for Simple rules', () => {
    const expertChain: ProxyChain = {
      id: 'chain-expert',
      name: 'Expert',
      strategy: 'failover',
      proxyIds: ['p1', 'p2'],
      enabled: true
    };
    expect(
      resolveSimpleProxyAction([sampleProxy('p1'), sampleProxy('p2')], [expertChain])
    ).toEqual({ type: 'proxy', targetId: 'p1' });
  });
});

describe('proxy removal plan', () => {
  const p1 = sampleProxy('p1');
  const p2 = sampleProxy('p2');
  const viaP1 = sampleRule({ id: 'a', action: { type: 'proxy', targetId: 'p1' } });
  const viaP2 = sampleRule({ id: 'b', action: { type: 'proxy', targetId: 'p2' } });
  const viaFailover = sampleRule({
    id: 'c',
    action: { type: 'chain', targetId: UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID }
  });
  const failover: ProxyChain = {
    id: UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID,
    name: 'Backup',
    strategy: 'failover',
    proxyIds: ['p1', 'p2'],
    enabled: true
  };

  it('retargets affected rules to the new primary proxy and drops the failover chain', () => {
    const plan = planProxyRemoval('p1', [p1, p2], [failover], [viaP1, viaP2, viaFailover]);
    expect(plan.newPrimary?.id).toBe('p2');
    expect(plan.affectedRules.map((r) => r.id)).toEqual(['a', 'c']);
    expect(plan.removeFailoverChain).toBe(true);
    expect(applyProxyRemovalToRule(viaP1, plan).action).toEqual({
      type: 'proxy',
      targetId: 'p2'
    });
  });

  it('disables affected rules instead of switching them to direct when no proxy is left', () => {
    const plan = planProxyRemoval('p1', [p1], [], [viaP1]);
    expect(plan.newPrimary).toBeNull();
    expect(plan.affectedEnabledCount).toBe(1);
    const next = applyProxyRemovalToRule(viaP1, plan);
    expect(next.enabled).toBe(false);
    expect(next.action).toEqual(viaP1.action);
  });

  it('keeps the failover chain when two proxies stay and leaves unrelated rules alone', () => {
    const p3 = sampleProxy('p3');
    const plan = planProxyRemoval('p1', [p1, p2, p3], [failover], [viaP2, viaFailover]);
    expect(plan.removeFailoverChain).toBe(false);
    expect(plan.affectedRules).toHaveLength(0);
  });
});

describe('proxy link parsing', () => {
  it('accepts a link without scheme and uses the default protocol', () => {
    const node = parseLooseProxyLink('1.2.3.4:8080', 'http');
    expect(node?.protocol).toBe('http');
    expect(node?.host).toBe('1.2.3.4');
    expect(node?.port).toBe(8080);
    expect(parseLooseProxyLink('user:pw@host.example:1080', 'socks5')?.auth?.username).toBe(
      'user'
    );
    expect(parseLooseProxyLink('socks5://h.example:1080', 'http')?.protocol).toBe('socks5');
  });

  it('rejects text that is not a proxy link', () => {
    expect(parseLooseProxyLink('not a link', 'http')).toBeNull();
    expect(parseLooseProxyLink('host-only', 'http')).toBeNull();
    expect(parseLooseProxyLink('host:99999999', 'http')).toBeNull();
    expect(parseLooseProxyLink('', 'http')).toBeNull();
  });

  it('splits host:port typed in the host field', () => {
    expect(splitHostAndPort('1.2.3.4:8080')).toEqual({ host: '1.2.3.4', port: 8080 });
    expect(splitHostAndPort('proxy.example.com')).toBeNull();
    expect(splitHostAndPort('proxy.example.com:0')).toBeNull();
  });

  it('prefixes scheme-less lines of a batch import only', () => {
    expect(
      normalizeProxyImportText('1.2.3.4:8080\nsocks5://a.example:1080\n# note', 'http')
    ).toBe('http://1.2.3.4:8080\nsocks5://a.example:1080\n# note');
  });
});
