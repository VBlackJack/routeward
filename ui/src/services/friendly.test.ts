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
  findShadowingRule,
  getFriendlyAppName,
  getHumanErrorKey,
  resolveSimpleProxyAction
} from './friendly';

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
