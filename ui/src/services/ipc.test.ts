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
import { SYSTEM_CONSTANTS, UI_CONFIG } from '../config/constants';
import {
  HttpResponseError,
  RouteWardClientService,
  parseSseChunk
} from './ipc';

describe('RouteWardClientService', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('parses proxy URIs with encoded credentials and colons in passwords', () => {
    const client = new RouteWardClientService();
    const parsed = client.parseSingleProxyUri(
      'socks5://user%40corp:p%3Ass%3Aword%25@proxy.example.com:1080?sni=edge.example.com#Corp%20Edge'
    );

    expect(parsed).not.toBeNull();
    expect(parsed?.protocol).toBe('socks5');
    expect(parsed?.host).toBe('proxy.example.com');
    expect(parsed?.port).toBe(1080);
    expect(parsed?.name).toBe('Corp Edge');
    expect(parsed?.sni).toBe('edge.example.com');
    expect(parsed?.tls).toBe(true);
    expect(parsed?.auth).toEqual({
      username: 'user@corp',
      hasPassword: true,
      password: 'p:ss:word%'
    });
  });

  it('does not crash when parsing malformed percent-encoded proxy URIs', () => {
    const client = new RouteWardClientService();
    const parsed = client.parseSingleProxyUri(
      'http://alice:%ZZbad@127.0.0.1:8080#Broken%ZZLabel'
    );

    expect(parsed).not.toBeNull();
    expect(parsed?.auth?.username).toBe('alice');
    expect(parsed?.auth?.password).toBe('%ZZbad');
    expect(parsed?.name).toBe('Broken%ZZLabel');
  });

  it('throws HttpResponseError on HTTP 4xx/5xx without marking daemon disconnected', async () => {
    const client = new RouteWardClientService();
    client.applyFullState({
      diagnostics: {
        ...client.getDiagnostics(),
        daemonConnected: true,
        running: true
      },
      profile: client.getProfile(),
      telemetry: client.getTelemetry(),
      connections: [],
      logs: [],
      fakeIps: []
    });

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({ error: 'Registry write denied' })
      })
    );

    await expect(client.setSystemProxy(true)).rejects.toBeInstanceOf(HttpResponseError);
    expect(client.getDiagnostics().daemonConnected).toBe(true);

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ error: 'Executable path is required' })
      })
    );

    await expect(client.launchProcessWithProxy('', [])).rejects.toThrow(
      'Executable path is required'
    );
    expect(client.getDiagnostics().daemonConnected).toBe(true);
  });

  it('marks daemon disconnected on transport-level network failure', async () => {
    const client = new RouteWardClientService();
    client.applyFullState({
      diagnostics: {
        ...client.getDiagnostics(),
        daemonConnected: true,
        running: true
      },
      profile: client.getProfile(),
      telemetry: client.getTelemetry(),
      connections: [],
      logs: [],
      fakeIps: []
    });

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));

    await expect(client.setSystemProxy(true)).rejects.toThrow('Failed to fetch');
    expect(client.getDiagnostics().daemonConnected).toBe(false);
    expect(client.getDiagnostics().running).toBe(false);
  });

  it('rejects malformed JSON and invalid profile shapes in importProfileJson', async () => {
    const client = new RouteWardClientService();

    await expect(client.importProfileJson('{not-json')).rejects.toThrow();
    await expect(client.importProfileJson('{"proxies":[]}')).rejects.toThrow(
      'Invalid profile structure'
    );
  });

  it('brackets and parses IPv6 proxy URIs cleanly', () => {
    const client = new RouteWardClientService();
    const formatted = client.formatProxyUri({
      id: 'p6',
      name: 'Edge v6',
      protocol: 'socks5',
      host: '2001:db8::1',
      port: 1080,
      auth: { username: 'alice', hasPassword: false },
      udpEnabled: true,
      tls: false,
      sni: null,
      enabled: true,
      lastLatencyMs: null,
      exitIp: null
    });
    expect(formatted).toBe('socks5://alice@[2001:db8::1]:1080#Edge%20v6');

    const parsed = client.parseSingleProxyUri(formatted);
    expect(parsed).not.toBeNull();
    expect(parsed?.host).toBe('2001:db8::1');
    expect(parsed?.port).toBe(1080);
    expect(parsed?.name).toBe('Edge v6');
    expect(parsed?.auth?.username).toBe('alice');
  });

  it('parses SSE chunks with CRLF, keepalive comments, multi-line data, and partial remainders', () => {
    const first = parseSseChunk(
      ': keepalive\r\n\r\nevent: resync\r\ndata: {"skippedEvents":2}\r\n\r\ndata: {"partial":'
    );
    expect(first.events).toEqual([
      { event: 'resync', data: '{"skippedEvents":2}' }
    ]);
    expect(first.remainder).toBe('data: {"partial":');

    const second = parseSseChunk(`${first.remainder}1}\n\n`);
    expect(second.events).toEqual([
      { event: 'message', data: '{"partial":1}' }
    ]);
    expect(second.remainder).toBe('');
  });

  it('applies SSE telemetry, connection, and log stream events accurately', () => {
    const client = new RouteWardClientService();
    expect(
      client.applyStreamEvent({ streamType: 'resync', payload: { skippedEvents: 0 } })
    ).toBe(true);

    client.applyFullState({
      diagnostics: {
        ...client.getDiagnostics(),
        daemonConnected: true,
        running: true
      },
      profile: client.getProfile(),
      telemetry: client.getTelemetry(),
      connections: [],
      logs: [],
      fakeIps: []
    });

    const needResync = client.applyStreamEvent({
      streamType: 'event',
      payload: {
        event: 'connectionUpdated',
        data: {
          id: 'conn-1',
          pid: 1234,
          processName: 'curl.exe',
          processPath: 'C:\\Windows\\System32\\curl.exe',
          targetHost: 'example.com',
          resolvedDomain: 'example.com',
          targetPort: 443,
          protocol: 'tcp',
          matchedRule: 'ProxyDefault',
          routeLabel: 'SOCKS5',
          latencyMs: 12,
          rxBytes: 100,
          txBytes: 200,
          status: 'active',
          startedAt: '2026-11-15T08:00:00Z'
        }
      }
    });
    expect(needResync).toBe(false);
    expect(client.listConnections()).toHaveLength(1);
    expect(client.getTelemetry().activeConnections).toBe(1);

    client.applyStreamEvent({
      streamType: 'event',
      payload: {
        event: 'log',
        data: {
          id: 'log-1',
          timestamp: '2026-11-15T08:00:01Z',
          level: 'INFO',
          component: 'Engine',
          message: 'Connected'
        }
      }
    });
    expect(client.listLogs()).toHaveLength(1);

    client.applyStreamEvent({
      streamType: 'event',
      payload: { event: 'logsCleared' }
    });
    expect(client.listLogs()).toHaveLength(0);
  });

  it('rethrows HttpResponseError with errorKey on toggleEngine 409 without marking daemon disconnected', async () => {
    const client = new RouteWardClientService();
    client.applyFullState({
      diagnostics: {
        ...client.getDiagnostics(),
        daemonConnected: true,
        running: false
      },
      profile: client.getProfile(),
      telemetry: client.getTelemetry(),
      connections: [],
      logs: [],
      fakeIps: []
    });

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: 'WinDivert driver DLL not found',
          errorKey: 'errors.interceptor.driver_missing'
        }),
        {
          status: 409,
          headers: { 'Content-Type': 'application/json' }
        }
      )
    );

    let caught: unknown = null;
    try {
      await client.toggleEngine(true);
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(HttpResponseError);
    expect((caught as HttpResponseError).status).toBe(409);
    expect((caught as HttpResponseError).errorKey).toBe(
      'errors.interceptor.driver_missing'
    );
    expect(client.getDiagnostics().daemonConnected).toBe(true);
  });

  it('bounds cached connections in applyStreamEvent while preserving active entries', () => {
    const client = new RouteWardClientService();
    const limit = SYSTEM_CONSTANTS.telemetry.maxConnectionHistoryEntries;
    const baseEntry = {
      pid: 4242,
      processName: 'chrome.exe',
      processPath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      targetHost: 'example.com',
      resolvedDomain: 'example.com',
      targetPort: 443,
      protocol: 'tcp' as const,
      matchedRule: 'Direct',
      routeLabel: 'DIRECT',
      latencyMs: 5,
      rxBytes: 64,
      txBytes: 32,
      startedAt: '2026-11-15T08:00:00Z'
    };

    client.applyStreamEvent({
      streamType: 'event',
      payload: {
        event: 'connectionUpdated',
        data: { ...baseEntry, id: 'conn-active-oldest', status: 'active' }
      }
    });

    for (let i = 0; i < limit + 15; i += 1) {
      client.applyStreamEvent({
        streamType: 'event',
        payload: {
          event: 'connectionUpdated',
          data: {
            ...baseEntry,
            id: `conn-closed-${i}`,
            status: 'closed'
          }
        }
      });
    }

    const connections = client.listConnections();
    expect(connections).toHaveLength(limit);
    expect(connections.some((c) => c.id === 'conn-active-oldest')).toBe(true);
  });

  it('rethrows HttpResponseError with errorKey from every mutation instead of swallowing it', async () => {
    const client = new RouteWardClientService();
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({
          error: 'Invalid proxy URI format',
          errorKey: 'errors.proxy.invalid_uri'
        })
      })
    );
    const node = client.parseSingleProxyUri('socks5://127.0.0.1:1080');
    expect(node).not.toBeNull();
    const profile = client.getProfile();
    const rule = profile.rules[0];

    const mutations: Array<() => Promise<unknown>> = [
      () => client.upsertProxy(node!),
      () => client.removeProxy('p1'),
      () =>
        client.upsertChain({
          id: 'c1',
          name: 'c',
          strategy: 'sequence',
          proxyIds: [],
          enabled: true
        }),
      () => client.removeChain('c1'),
      () => client.upsertRule(rule),
      () => client.removeRule('r1'),
      () => client.setInterceptionMode('relay'),
      () => client.replaceProfile(profile),
      () => client.updateSecurityPolicy({ killSwitchEnabled: false }),
      () => client.terminateConnection('conn-1'),
      () => client.clearClosedConnections(),
      () => client.flushFakeIps(),
      () => client.clearLogs(),
      () => client.allocateFakeIp('example.com'),
      () => client.testProxy('p1'),
      () => client.testAllProxies()
    ];
    for (const mutation of mutations) {
      await expect(mutation()).rejects.toMatchObject({
        name: 'HttpResponseError',
        status: 400,
        errorKey: 'errors.proxy.invalid_uri'
      });
    }
    expect(client.getDiagnostics().daemonConnected).toBe(false);
  });

  it('marks the client disconnected and rejects mutations on network errors', async () => {
    const client = new RouteWardClientService();
    client.applyFullState({
      diagnostics: {
        ...client.getDiagnostics(),
        daemonConnected: true,
        running: true
      },
      profile: client.getProfile(),
      telemetry: client.getTelemetry(),
      connections: [],
      logs: [],
      fakeIps: []
    });
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));

    // An unreachable bridge must not look like a success to the caller.
    await expect(client.setInterceptionMode('relay')).rejects.toThrow('Failed to fetch');
    expect(client.getDiagnostics().daemonConnected).toBe(false);
    await expect(client.clearClosedConnections()).rejects.toThrow('Failed to fetch');
  });

  it('treats terminated:false as a failed termination', async () => {
    const client = new RouteWardClientService();
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ terminated: false })
      })
    );
    await expect(client.terminateConnection('conn-1')).rejects.toBeInstanceOf(
      HttpResponseError
    );
  });

  it('reads the allocated fake IP from the bridge response', async () => {
    const client = new RouteWardClientService();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ allocated: '198.18.0.7', entries: [] })
      })
      .mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({})
      });
    vi.stubGlobal('fetch', fetchMock);
    await expect(client.allocateFakeIp('Example.com')).resolves.toBe('198.18.0.7');
  });

  it('reads the system proxy switch with a GET and falls back to off on failure', async () => {
    const client = new RouteWardClientService();
    const fetchMock = vi.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ enabled: true })
    });
    vi.stubGlobal('fetch', fetchMock);
    await expect(client.getSystemProxyStatus()).resolves.toEqual({ enabled: true });
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain('/api/system-proxy');
    expect(init.method).toBe('GET');

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    await expect(client.getSystemProxyStatus()).resolves.toEqual({ enabled: false });
  });

  it('coalesces listener notifications of an SSE burst into a single pass', () => {
    vi.useFakeTimers();
    try {
      const client = new RouteWardClientService();
      const listener = vi.fn();
      client.subscribe(listener);
      for (let i = 0; i < 20; i += 1) {
        client.applyStreamEvent({
          streamType: 'event',
          payload: {
            event: 'log',
            data: {
              id: `burst-id-${i}`,
              timestamp: '2026-11-16T08:00:00Z',
              level: 'INFO',
              component: 'test',
              message: `burst-${i}`
            }
          }
        });
      }
      expect(listener).not.toHaveBeenCalled();
      vi.advanceTimersByTime(UI_CONFIG.STREAM_NOTIFY_COALESCE_MS + 1);
      expect(listener).toHaveBeenCalledTimes(1);
      expect(client.listLogs()).toHaveLength(20);
    } finally {
      vi.useRealTimers();
    }
  });

  it('restarts the realtime stream for a new AbortSignal after the previous one was aborted', async () => {
    const fetchMock = vi.fn().mockImplementation(
      (_url: string, init?: { signal?: AbortSignal }) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(new DOMException('aborted', 'AbortError'))
          );
        })
    );
    vi.stubGlobal('fetch', fetchMock);
    const client = new RouteWardClientService();

    const first = new AbortController();
    client.startRealtimeStream(first.signal);
    const callsAfterFirst = fetchMock.mock.calls.length;
    // Same live signal: ignored
    client.startRealtimeStream(first.signal);
    expect(fetchMock.mock.calls.length).toBe(callsAfterFirst);

    first.abort();
    const second = new AbortController();
    client.startRealtimeStream(second.signal);
    await vi.waitFor(() => {
      expect(fetchMock.mock.calls.length).toBeGreaterThan(callsAfterFirst);
    });
    second.abort();
  });

  it('rejects out-of-range or non-numeric ports in proxy URIs', () => {
    const client = new RouteWardClientService();
    expect(client.parseSingleProxyUri('socks5://127.0.0.1:70000')).toBeNull();
    expect(client.parseSingleProxyUri('socks5://127.0.0.1:65536')).toBeNull();
    expect(client.parseSingleProxyUri('socks5://127.0.0.1:1e3')).toBeNull();
    expect(client.parseSingleProxyUri('socks5://127.0.0.1:0')).toBeNull();
    expect(client.parseSingleProxyUri('socks5://127.0.0.1:65535')?.port).toBe(65535);
  });
});
