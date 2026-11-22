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

import { afterEach, describe, expect, it, vi } from 'vitest';
import { UI_CONFIG } from '../config/constants';
import { TrackedConnection } from '../types/routeward';
import {
  connectionNeedsExplanation,
  explainConnection,
  findConnectionToExplain
} from './activityWhy';
import { RouteWardClientService } from './ipc';
import {
  buildWizardSummaryKeys,
  countAddedProxies,
  getWizardPresetIds
} from './wizardPlan';

function connection(overrides: Partial<TrackedConnection>): TrackedConnection {
  return {
    id: 'c1',
    pid: 1,
    processName: 'firefox.exe',
    processPath: '',
    targetHost: 'example.com',
    resolvedDomain: null,
    targetPort: 443,
    protocol: 'tcp',
    matchedRule: 'Direct',
    routeLabel: 'DIRECT',
    latencyMs: 0,
    rxBytes: 0,
    txBytes: 0,
    status: 'active',
    startedAt: '2026-11-22T10:00:00Z',
    ...overrides
  };
}

describe('wizard plan', () => {
  it('only lists rules that need a proxy when one is configured', () => {
    expect(getWizardPresetIds('privacy', false)).toEqual([
      'preset-block-os-telemetry',
      'preset-rfc1918-direct'
    ]);
    expect(getWizardPresetIds('privacy', true)).toContain('preset-privacy-browsers');
    expect(getWizardPresetIds('work', false)).toEqual(['preset-rfc1918-direct']);
  });

  it('promises telemetry blocking only when a blocking rule is created', () => {
    expect(buildWizardSummaryKeys('privacy', true)).toContain('wizard.summary.block_telemetry');
    expect(buildWizardSummaryKeys('work', true)).not.toContain('wizard.summary.block_telemetry');
    expect(buildWizardSummaryKeys('gaming', true)).not.toContain('wizard.summary.block_telemetry');
  });

  it('warns that the IP address stays visible when there is no proxy', () => {
    expect(buildWizardSummaryKeys('privacy', false)).toContain(
      'wizard.summary.no_proxy_ip_visible'
    );
    expect(buildWizardSummaryKeys('privacy', true)).not.toContain(
      'wizard.summary.no_proxy_ip_visible'
    );
  });

  it('counts only the proxies an import really added', () => {
    expect(countAddedProxies([{ id: 'a' }], [{ id: 'a' }])).toBe(0);
    expect(countAddedProxies([{ id: 'a' }], [{ id: 'a' }, { id: 'b' }])).toBe(1);
  });
});

describe('activity why', () => {
  const t = (key: string) => (key === 'rules.generated.default_policy' ? 'Default behavior' : key);

  it('explains blocked or failed connections only', () => {
    expect(connectionNeedsExplanation(connection({}))).toBe(false);
    expect(connectionNeedsExplanation(connection({ status: 'blocked' }))).toBe(true);
    expect(connectionNeedsExplanation(connection({ errorDetail: 'timeout' }))).toBe(true);
  });

  it('returns the localized rule name and the translated reason key', () => {
    const explanation = explainConnection(
      connection({
        status: 'blocked',
        matchedRule: UI_CONFIG.ENGINE_DEFAULT_RULE_NAME,
        errorDetail: 'kill-switch'
      }),
      t
    );
    expect(explanation.ruleName).toBe('Default behavior');
    expect(explanation.reasonKey).toBe('troubleshoot.reasons.killswitch');
  });

  it('finds the failing connection of an application, case-insensitively', () => {
    const connections = [
      connection({ id: 'ok' }),
      connection({ id: 'bad', processName: 'Firefox.EXE', status: 'blocked' })
    ];
    expect(findConnectionToExplain(connections, 'firefox.exe')?.id).toBe('bad');
    expect(findConnectionToExplain(connections, 'chrome.exe')).toBeNull();
  });
});

describe('pauseEngine', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('asks the daemon to pause for the given number of seconds', async () => {
    const client = new RouteWardClientService();
    const paused = {
      ...client.getDiagnostics(),
      daemonConnected: true,
      running: false,
      pausedUntilEpochMs: 1_900_000_000_000
    };
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes(UI_CONFIG.API_ENDPOINTS.ENGINE_PAUSE)) {
        return new Response(JSON.stringify(paused), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      return new Response(
        JSON.stringify({
          diagnostics: paused,
          profile: client.getProfile(),
          telemetry: client.getTelemetry(),
          connections: [],
          logs: [],
          fakeIps: []
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    });

    const diag = await client.pauseEngine(900);

    expect(diag.pausedUntilEpochMs).toBe(1_900_000_000_000);
    const pauseCall = fetchSpy.mock.calls.find((call) =>
      String(call[0]).includes(UI_CONFIG.API_ENDPOINTS.ENGINE_PAUSE)
    );
    expect(pauseCall).toBeDefined();
    expect(JSON.parse(String((pauseCall?.[1] as RequestInit).body))).toEqual({
      seconds: 900
    });
  });
});
