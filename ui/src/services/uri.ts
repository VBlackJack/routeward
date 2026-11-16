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

import { UI_CONFIG } from '../config/constants';
import { ProxyNode, ProxyProtocol } from '../types/routeward';

const PORT_PATTERN = /^\d{1,5}$/;

let idSequenceCounter = 0;

function safeDecodeURIComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function generateClientId(prefix: string): string {
  idSequenceCounter += 1;
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `${prefix}-${crypto.randomUUID()}`;
  }
  return `${prefix}-${Date.now()}-${idSequenceCounter}`;
}

export function sanitizeProxyNodeForWrite(node: ProxyNode): ProxyNode {
  if (!node.auth) {
    return { ...node, auth: null };
  }
  const cleanUser = node.auth.username.trim();
  const rawPass = node.auth.password;
  const hasNewPassword = typeof rawPass === 'string' && rawPass.length > 0;

  if (!cleanUser && !hasNewPassword && !node.auth.hasPassword) {
    return { ...node, auth: null };
  }

  const sanitizedAuth: NonNullable<ProxyNode['auth']> = {
    username: cleanUser,
    hasPassword: hasNewPassword ? true : Boolean(node.auth.hasPassword)
  };
  if (hasNewPassword) {
    sanitizedAuth.password = rawPass;
  }

  return {
    ...node,
    auth: sanitizedAuth
  };
}

export function formatProxyHostPort(host: string, port: number): string {
  const cleanHost = host.trim();
  if (cleanHost.includes(':') && !cleanHost.startsWith('[')) {
    return `[${cleanHost}]:${port}`;
  }
  return `${cleanHost}:${port}`;
}

export function formatProxyUri(node: ProxyNode): string {
  const scheme = node.protocol;
  const authPart =
    node.auth && node.auth.username
      ? `${encodeURIComponent(node.auth.username)}@`
      : '';
  const queryParams: string[] = [];
  if (node.sni) {
    queryParams.push(`sni=${encodeURIComponent(node.sni)}`);
  }
  if (node.tls && node.tlsSkipVerify) {
    queryParams.push('insecure=1');
  }
  const queryPart = queryParams.length > 0 ? `?${queryParams.join('&')}` : '';
  const hashPart = `#${encodeURIComponent(node.name)}`;
  const hostPort = formatProxyHostPort(node.host, node.port);
  return `${scheme}://${authPart}${hostPort}${queryPart}${hashPart}`;
}

export function parseSingleProxyUri(uri: string): ProxyNode | null {
  const match = uri.match(/^([a-zA-Z0-9]+):\/\/([^?#]+)(\?[^#]*)?(#.*)?$/);
  if (!match) return null;
  const rawScheme = match[1].toLowerCase();
  const authority = match[2];
  const query = match[3] || '';
  const fragment = match[4] ? safeDecodeURIComponent(match[4].slice(1)) : '';

  const protocolMap: Record<string, ProxyProtocol> = {
    socks5: 'socks5',
    socks4: 'socks4',
    socks4a: 'socks4',
    http: 'http',
    https: 'https'
  };
  const protocol = protocolMap[rawScheme];
  if (!protocol) return null;

  let userInfo = '';
  let hostPort = authority;
  if (authority.includes('@')) {
    const atIdx = authority.lastIndexOf('@');
    userInfo = authority.slice(0, atIdx);
    hostPort = authority.slice(atIdx + 1);
  }

  let host: string;
  let portStr: string;
  if (hostPort.startsWith('[')) {
    const closeBracket = hostPort.indexOf(']');
    if (closeBracket <= 1 || hostPort[closeBracket + 1] !== ':') {
      return null;
    }
    host = hostPort.slice(1, closeBracket);
    portStr = hostPort.slice(closeBracket + 2);
  } else {
    const colonIdx = hostPort.lastIndexOf(':');
    if (colonIdx <= 0) return null;
    host = hostPort.slice(0, colonIdx);
    portStr = hostPort.slice(colonIdx + 1);
  }

  const portText = portStr.replace(/\/$/, '');
  if (!PORT_PATTERN.test(portText)) return null;
  const port = Number(portText);
  if (!host || port <= 0 || port > UI_CONFIG.MAX_PORT) return null;

  let auth: ProxyNode['auth'] = null;
  if (userInfo) {
    const firstColon = userInfo.indexOf(':');
    const rawUser = firstColon >= 0 ? userInfo.slice(0, firstColon) : userInfo;
    const rawPass = firstColon >= 0 ? userInfo.slice(firstColon + 1) : '';
    const decodedPass = safeDecodeURIComponent(rawPass);
    auth = {
      username: safeDecodeURIComponent(rawUser),
      ...(decodedPass
        ? { password: decodedPass, hasPassword: true }
        : { hasPassword: false })
    };
  }

  const params = new URLSearchParams(query.replace(/^\?/, ''));
  let sni: string | null = null;
  let insecureVal = '';
  for (const [key, val] of params.entries()) {
    const low = key.toLowerCase();
    if (low === 'sni' && val) {
      sni = val;
    } else if (low === 'insecure' || low === 'skipverify' || low === 'tlsskipverify') {
      insecureVal = val.toLowerCase();
    }
  }
  const tls = protocol === 'https' || Boolean(sni);
  const tlsSkipVerify = insecureVal === '1' || insecureVal === 'true' || insecureVal === 'yes';

  return {
    id: generateClientId('proxy'),
    name: fragment || `${protocol.toUpperCase()} ${formatProxyHostPort(host, port)}`,
    protocol,
    host,
    port,
    auth,
    udpEnabled: protocol === 'socks5',
    tls,
    tlsSkipVerify,
    sni,
    enabled: true,
    lastLatencyMs: null,
    exitIp: null
  };
}
