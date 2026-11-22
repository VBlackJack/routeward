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
import en from '../../../locales/en.json';
import fr from '../../../locales/fr.json';
import { ProxyNode } from '../types/routeward';
import {
  computeProtectionHealth,
  formatPauseEnd,
  PROTECTION_HEALTH_TEXTS,
  ProtectionHealthInput,
  resolveProxyReachability,
  secondsUntil
} from './protectionHealth';

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

function input(
  overrides: Partial<ProtectionHealthInput['diagnostics']>,
  primaryProxy: ProxyNode | null,
  proxyReachability: ProtectionHealthInput['proxyReachability'] = 'unknown'
): ProtectionHealthInput {
  return {
    diagnostics: {
      daemonConnected: true,
      running: true,
      pausedUntilEpochMs: null,
      autoStartErrorKey: null,
      ...overrides
    },
    primaryProxy,
    proxyReachability
  };
}

function lookup(root: unknown, key: string): unknown {
  return key
    .split('.')
    .reduce<unknown>((node, part) => (node as Record<string, unknown>)?.[part], root);
}

describe('computeProtectionHealth', () => {
  it('reports a stopped service when the daemon is not reachable', () => {
    const health = computeProtectionHealth(
      input({ daemonConnected: false, running: false }, proxy)
    );
    expect(health.state).toBe('service_stopped');
    expect(health.engineActive).toBe(false);
    expect(health.ipHidden).toBe(false);
  });

  it('reports protection off when the service runs but the engine is stopped', () => {
    expect(
      computeProtectionHealth(input({ running: false }, proxy)).state
    ).toBe('stopped');
  });

  it('reports a pause with its end time, and never counts it as active', () => {
    const health = computeProtectionHealth(
      input({ running: false, pausedUntilEpochMs: 1_800_000_000_000 }, proxy)
    );
    expect(health.state).toBe('paused');
    expect(health.pausedUntilEpochMs).toBe(1_800_000_000_000);
    expect(health.engineActive).toBe(false);
    expect(health.ipHidden).toBe(false);
  });

  it('reports the automatic start error with its key', () => {
    const health = computeProtectionHealth(
      input({ running: false, autoStartErrorKey: 'errors.interceptor.driver_missing' }, null)
    );
    expect(health.state).toBe('error');
    expect(health.errorKey).toBe('errors.interceptor.driver_missing');
  });

  it('only claims a hidden IP address when the proxy answered its test', () => {
    const ok = computeProtectionHealth(input({}, proxy, 'reachable'));
    expect(ok.state).toBe('active_proxy_ok');
    expect(ok.ipHidden).toBe(true);

    const untested = computeProtectionHealth(input({}, proxy, 'unknown'));
    expect(untested.state).toBe('active_proxy_untested');
    expect(untested.ipHidden).toBe(false);

    const down = computeProtectionHealth(input({}, proxy, 'unreachable'));
    expect(down.state).toBe('active_proxy_unreachable');
    expect(down.ipHidden).toBe(false);
  });

  it('never claims a hidden IP address when there is no proxy', () => {
    const health = computeProtectionHealth(input({}, null, 'reachable'));
    expect(health.state).toBe('active_no_proxy');
    expect(health.engineActive).toBe(true);
    expect(health.ipHidden).toBe(false);
  });

  it('has EN and FR texts for every state', () => {
    for (const texts of Object.values(PROTECTION_HEALTH_TEXTS)) {
      for (const key of Object.values(texts)) {
        expect(typeof lookup(en, key)).toBe('string');
        expect(typeof lookup(fr, key)).toBe('string');
      }
    }
  });
});

describe('resolveProxyReachability', () => {
  it('prefers a recorded failure, then a recorded success, then the stored latency', () => {
    expect(resolveProxyReachability(null, [], [], false)).toBe('unknown');
    expect(resolveProxyReachability(proxy, ['p1'], ['p1'], false)).toBe('unreachable');
    expect(resolveProxyReachability(proxy, [], ['p1'], false)).toBe('reachable');
    expect(resolveProxyReachability(proxy, [], [], true)).toBe('unreachable');
    expect(
      resolveProxyReachability({ ...proxy, lastLatencyMs: 40 }, [], [], false)
    ).toBe('reachable');
    expect(resolveProxyReachability(proxy, [], [], false)).toBe('unknown');
  });
});

describe('pause helpers', () => {
  it('formats the end of a pause as a 24-hour wall-clock time', () => {
    const noon = new Date(2026, 10, 22, 14, 5, 0).getTime();
    expect(formatPauseEnd(noon, 'en')).toMatch(/^14:05$/);
  });

  it('counts the seconds left and never goes below zero', () => {
    expect(secondsUntil(10_500, 10_000)).toBe(1);
    expect(secondsUntil(10_000, 10_000)).toBe(0);
    expect(secondsUntil(9_000, 10_000)).toBe(0);
  });
});
