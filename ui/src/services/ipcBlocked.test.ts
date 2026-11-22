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
import { RouteWardClientService } from './ipc';

function mockFetch(body: unknown) {
  const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => body });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('blocked, logs, diagnostics and preview calls', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('reads the blocked summary with GET /api/blocked', async () => {
    const payload = {
      entries: [],
      counters: { droppedUnattributedSyn: 1, droppedUnattributedUdp: 2 }
    };
    const fetchMock = mockFetch(payload);
    const result = await new RouteWardClientService().getBlocked();
    expect(result).toEqual(payload);
    expect(fetchMock.mock.calls[0][0]).toBe(UI_CONFIG.API_ENDPOINTS.BLOCKED);
    expect(fetchMock.mock.calls[0][1].method).toBe('GET');
  });

  it('passes since and limit as query parameters when asked', async () => {
    const fetchMock = mockFetch({ entries: [], counters: {} });
    await new RouteWardClientService().getBlocked({ since: 1000, limit: 50 });
    expect(fetchMock.mock.calls[0][0]).toBe('/api/blocked?since=1000&limit=50');
  });

  it('returns null instead of throwing when the bridge is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('network')));
    expect(await new RouteWardClientService().getBlocked()).toBeNull();
  });

  it('posts the log query as is to /api/logs/query', async () => {
    const response = { entries: [], truncated: false, availableDates: ['20261122'] };
    const fetchMock = mockFetch(response);
    const req = { source: { daemonFile: { date: '20261122' } }, limit: 200, text: 'x' };
    expect(await new RouteWardClientService().queryLogs(req)).toEqual(response);
    expect(fetchMock.mock.calls[0][0]).toBe('/api/logs/query');
    expect(fetchMock.mock.calls[0][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual(req);
  });

  it('posts analyze and collect to the diagnostics routes', async () => {
    const fetchMock = mockFetch({ findings: [] });
    const client = new RouteWardClientService();
    await client.analyzeDiagnostics();
    expect(fetchMock.mock.calls[0][0]).toBe('/api/diagnostics/analyze');

    const collect = {
      logDays: 3,
      includeConnections: true,
      includeProfile: false,
      maskDomains: true
    };
    await client.collectDiagnostics(collect);
    expect(fetchMock.mock.calls[1][0]).toBe('/api/diagnostics/collect');
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual(collect);
  });

  it('posts the rule preview and returns null when it is unavailable', async () => {
    const response = {
      evaluation: {
        matchedRuleId: 'r',
        matchedRuleName: 'R',
        action: { type: 'direct' },
        effectiveDomain: null,
        resolvedFromFakeIp: false
      },
      policyOverride: 'killSwitchProxyUnreachable'
    };
    const fetchMock = mockFetch(response);
    const client = new RouteWardClientService();
    const req = {
      upserts: [],
      removeIds: ['rule-x'],
      request: {
        processName: 'a.exe',
        targetHost: 'h',
        targetPort: 1,
        protocol: 'tcp' as const
      }
    };
    expect(await client.previewRuleChange(req)).toEqual(response);
    expect(fetchMock.mock.calls[0][0]).toBe('/api/rules/preview');

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('network')));
    expect(await client.previewRuleChange(req)).toBeNull();
  });
});
