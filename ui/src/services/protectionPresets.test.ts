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
import { ProxyNode, SecurityPolicyConfig } from '../types/routeward';
import {
  diffSecurityChanges,
  isShieldFullyOn,
  isUseCaseApplied,
  planShieldToggle,
  planUseCase,
  readShieldMix
} from './protectionPresets';

const proxy: ProxyNode = {
  id: 'p1',
  name: 'Proxy',
  protocol: 'socks5',
  host: 'proxy.example.com',
  port: 1080,
  auth: null,
  udpEnabled: true,
  tls: false,
  sni: null,
  enabled: true,
  lastLatencyMs: null,
  exitIp: null
};

const lowPolicy: SecurityPolicyConfig = {
  killSwitchEnabled: false,
  blockUdpOnTcpOnlyProxy: true,
  strictDnsNoLocalFallback: false,
  blockQuicUdp443: false,
  blockEncryptedDnsBypass: false
};

const fullPolicy: SecurityPolicyConfig = {
  killSwitchEnabled: true,
  blockUdpOnTcpOnlyProxy: true,
  strictDnsNoLocalFallback: true,
  blockQuicUdp443: true,
  blockEncryptedDnsBypass: true
};

describe('all-in-one shield', () => {
  it('remembers the user mix when turned on and puts it back when turned off', () => {
    const on = planShieldToggle(lowPolicy, true, null);
    expect(on.apply).toEqual({
      killSwitchEnabled: true,
      blockUdpOnTcpOnlyProxy: true,
      strictDnsNoLocalFallback: true,
      blockQuicUdp443: true,
      blockEncryptedDnsBypass: true
    });
    expect(on.remember).toEqual(readShieldMix(lowPolicy));
    expect(on.undo).toEqual(readShieldMix(lowPolicy));

    const off = planShieldToggle(fullPolicy, false, on.remember);
    expect(off.apply).toEqual(readShieldMix(lowPolicy));
    expect(off.remember).toBeNull();
    expect(off.undo).toEqual(readShieldMix(fullPolicy));
  });

  it('turns every switch off when there is no remembered mix', () => {
    const off = planShieldToggle(fullPolicy, false, null);
    expect(Object.values(off.apply).every((value) => value === false)).toBe(true);
  });

  it('does not restore a remembered mix that is itself fully on', () => {
    const off = planShieldToggle(fullPolicy, false, readShieldMix(fullPolicy));
    expect(Object.values(off.apply).every((value) => value === false)).toBe(true);
  });

  it('counts missing optional switches as on', () => {
    expect(
      isShieldFullyOn({
        killSwitchEnabled: true,
        blockUdpOnTcpOnlyProxy: true,
        strictDnsNoLocalFallback: true
      })
    ).toBe(true);
  });
});

describe('use-case cards', () => {
  const t = (key: string) => key;

  it('lists only the switches that really change', () => {
    const { changed, previous } = diffSecurityChanges(lowPolicy, {
      killSwitchEnabled: true,
      blockUdpOnTcpOnlyProxy: true
    });
    expect(changed).toEqual(['killSwitchEnabled']);
    expect(previous).toEqual({ killSwitchEnabled: false });
  });

  it('skips proxy rules when no proxy is set up and says so', () => {
    const noProxy = planUseCase('work', { t, proxies: [], chains: [] });
    expect(noProxy.skippedProxyRule).toBe(true);
    expect(noProxy.rules.map((r) => r.id)).toEqual(['rule-uc-preset-rfc1918-direct']);

    const withProxy = planUseCase('work', { t, proxies: [proxy], chains: [] });
    expect(withProxy.skippedProxyRule).toBe(false);
    expect(withProxy.rules.map((r) => r.id)).toContain('rule-uc-preset-dev-toolchains');
  });

  it('derives the applied badge from the real profile, not from a click', () => {
    const plan = planUseCase('strict', { t, proxies: [], chains: [] });
    expect(isUseCaseApplied('strict', fullPolicy, [], [], [])).toBe(false);
    expect(isUseCaseApplied('strict', fullPolicy, plan.rules, [], [])).toBe(true);
    expect(isUseCaseApplied('strict', lowPolicy, plan.rules, [], [])).toBe(false);
    const disabled = plan.rules.map((rule) => ({ ...rule, enabled: false }));
    expect(isUseCaseApplied('strict', fullPolicy, disabled, [], [])).toBe(false);
  });
});
