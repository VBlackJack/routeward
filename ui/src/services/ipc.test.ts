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
});
