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
import { ProxyNode } from '../types/routeward';
import {
  formatProxyHostPort,
  formatProxyUri,
  generateClientId,
  parseSingleProxyUri,
  sanitizeProxyNodeForWrite
} from './uri';

function makeNode(overrides: Partial<ProxyNode> = {}): ProxyNode {
  return {
    id: 'proxy-1',
    name: 'Edge',
    protocol: 'socks5',
    host: 'proxy.example.com',
    port: 1080,
    auth: null,
    udpEnabled: true,
    tls: false,
    sni: null,
    enabled: true,
    lastLatencyMs: null,
    exitIp: null,
    ...overrides
  };
}

describe('formatProxyHostPort', () => {
  it('brackets bare IPv6 hosts and trims whitespace', () => {
    expect(formatProxyHostPort('  proxy.example.com ', 8080)).toBe('proxy.example.com:8080');
    expect(formatProxyHostPort('::1', 1080)).toBe('[::1]:1080');
  });

  it('does not bracket an already bracketed IPv6 host', () => {
    expect(formatProxyHostPort('[2001:db8::1]', 443)).toBe('[2001:db8::1]:443');
  });
});

describe('parseSingleProxyUri', () => {
  it('rejects malformed input', () => {
    expect(parseSingleProxyUri('')).toBeNull();
    expect(parseSingleProxyUri('not a uri')).toBeNull();
    expect(parseSingleProxyUri('socks5://')).toBeNull();
    expect(parseSingleProxyUri('socks5://hostonly')).toBeNull();
  });

  it('rejects unknown schemes', () => {
    expect(parseSingleProxyUri('ftp://proxy.example.com:21')).toBeNull();
    expect(parseSingleProxyUri('vmess://proxy.example.com:443')).toBeNull();
  });

  it('rejects out-of-range and non-numeric ports', () => {
    expect(parseSingleProxyUri('socks5://proxy.example.com:0')).toBeNull();
    expect(parseSingleProxyUri(`socks5://proxy.example.com:${UI_CONFIG.MAX_PORT + 1}`)).toBeNull();
    expect(parseSingleProxyUri('socks5://proxy.example.com:abc')).toBeNull();
    expect(parseSingleProxyUri('socks5://proxy.example.com:')).toBeNull();
    expect(parseSingleProxyUri('socks5://proxy.example.com:-1')).toBeNull();
  });

  it('accepts the maximum port', () => {
    const node = parseSingleProxyUri(`http://proxy.example.com:${UI_CONFIG.MAX_PORT}`);
    expect(node?.port).toBe(UI_CONFIG.MAX_PORT);
  });

  it('parses bracketed IPv6 hosts and rejects broken brackets', () => {
    const node = parseSingleProxyUri('socks5://[2001:db8::1]:1080#v6');
    expect(node?.host).toBe('2001:db8::1');
    expect(node?.port).toBe(1080);
    expect(parseSingleProxyUri('socks5://[2001:db8::1]1080')).toBeNull();
    expect(parseSingleProxyUri('socks5://[]:1080')).toBeNull();
  });

  it('maps socks4a to socks4 and is case-insensitive on the scheme', () => {
    expect(parseSingleProxyUri('SOCKS4a://proxy.example.com:1080')?.protocol).toBe('socks4');
    expect(parseSingleProxyUri('HTTP://proxy.example.com:3128')?.protocol).toBe('http');
  });

  it('enables UDP only for socks5', () => {
    expect(parseSingleProxyUri('socks5://proxy.example.com:1080')?.udpEnabled).toBe(true);
    expect(parseSingleProxyUri('http://proxy.example.com:3128')?.udpEnabled).toBe(false);
  });

  it('derives TLS from https or from an sni parameter', () => {
    expect(parseSingleProxyUri('https://proxy.example.com:443')?.tls).toBe(true);
    const withSni = parseSingleProxyUri('http://proxy.example.com:443?sni=edge.example.com');
    expect(withSni?.tls).toBe(true);
    expect(withSni?.sni).toBe('edge.example.com');
    expect(parseSingleProxyUri('http://proxy.example.com:3128')?.tls).toBe(false);
  });

  it('reads the insecure flag under its accepted spellings', () => {
    for (const query of ['insecure=1', 'skipVerify=true', 'tlsSkipVerify=YES']) {
      const node = parseSingleProxyUri(`https://proxy.example.com:443?${query}`);
      expect(node?.tlsSkipVerify, query).toBe(true);
    }
    expect(
      parseSingleProxyUri('https://proxy.example.com:443?insecure=0')?.tlsSkipVerify
    ).toBe(false);
  });

  it('keeps colons and encoded characters in credentials', () => {
    const node = parseSingleProxyUri('socks5://user:p%40ss:word@proxy.example.com:1080');
    expect(node?.auth).toEqual({
      username: 'user',
      password: 'p@ss:word',
      hasPassword: true
    });
  });

  it('splits credentials on the last at sign', () => {
    const node = parseSingleProxyUri('socks5://user@corp:secret@proxy.example.com:1080');
    expect(node?.host).toBe('proxy.example.com');
    expect(node?.auth?.username).toBe('user@corp');
    expect(node?.auth?.password).toBe('secret');
  });

  it('records a username without password', () => {
    const node = parseSingleProxyUri('socks5://alice@proxy.example.com:1080');
    expect(node?.auth).toEqual({ username: 'alice', hasPassword: false });
  });

  it('tolerates a trailing slash after the port', () => {
    expect(parseSingleProxyUri('http://proxy.example.com:3128/')?.port).toBe(3128);
  });

  it('falls back to a generated name and keeps an undecodable fragment as is', () => {
    expect(parseSingleProxyUri('socks5://proxy.example.com:1080')?.name).toBe(
      'SOCKS5 proxy.example.com:1080'
    );
    expect(parseSingleProxyUri('socks5://proxy.example.com:1080#100%')?.name).toBe('100%');
  });
});

describe('formatProxyUri', () => {
  it('round-trips through parseSingleProxyUri', () => {
    const node = makeNode({
      protocol: 'https',
      tls: true,
      tlsSkipVerify: true,
      sni: 'edge.example.com',
      name: 'Corp Edge',
      auth: { username: 'user@corp', hasPassword: true, password: 'x' }
    });
    const parsed = parseSingleProxyUri(formatProxyUri(node));
    expect(parsed).not.toBeNull();
    expect(parsed?.protocol).toBe('https');
    expect(parsed?.host).toBe(node.host);
    expect(parsed?.port).toBe(node.port);
    expect(parsed?.name).toBe('Corp Edge');
    expect(parsed?.sni).toBe('edge.example.com');
    expect(parsed?.tlsSkipVerify).toBe(true);
    expect(parsed?.auth?.username).toBe('user@corp');
  });

  it('never writes the password and omits the query when empty', () => {
    const uri = formatProxyUri(
      makeNode({ auth: { username: 'bob', hasPassword: true, password: 'secret' } })
    );
    expect(uri).toBe('socks5://bob@proxy.example.com:1080#Edge');
    expect(uri).not.toContain('secret');
  });
});

describe('sanitizeProxyNodeForWrite', () => {
  it('drops empty credentials', () => {
    const node = makeNode({ auth: { username: '  ', hasPassword: false } });
    expect(sanitizeProxyNodeForWrite(node).auth).toBeNull();
    expect(sanitizeProxyNodeForWrite(makeNode()).auth).toBeNull();
  });

  it('keeps a stored password flag without resending the password', () => {
    const node = makeNode({ auth: { username: ' bob ', hasPassword: true } });
    expect(sanitizeProxyNodeForWrite(node).auth).toEqual({
      username: 'bob',
      hasPassword: true
    });
  });

  it('forwards a new password', () => {
    const node = makeNode({ auth: { username: 'bob', hasPassword: false, password: 'new' } });
    expect(sanitizeProxyNodeForWrite(node).auth).toEqual({
      username: 'bob',
      hasPassword: true,
      password: 'new'
    });
  });
});

describe('generateClientId', () => {
  it('produces distinct prefixed identifiers', () => {
    const first = generateClientId('proxy');
    const second = generateClientId('proxy');
    expect(first.startsWith('proxy-')).toBe(true);
    expect(first).not.toBe(second);
  });
});
