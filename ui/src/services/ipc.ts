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

import {
  DEFAULT_PROFILE_DATA,
  SYSTEM_CONSTANTS,
  UI_CONFIG
} from '../config/constants';
import {
  ConnectionRequest,
  DaemonFullState,
  FakeIpEntry,
  InterceptionMode,
  IpcStreamEvent,
  LogEntry,
  ProcessTrafficSummary,
  ProfileConfig,
  ProxyChain,
  ProxyHealthReport,
  ProxyNode,
  ProxyProtocol,
  RoutingRule,
  RuleEvaluationResult,
  SecurityPolicyConfig,
  SystemDiagnostics,
  TelemetryEventPayload,
  TelemetrySnapshot,
  TrackedConnection
} from '../types/routeward';

const PRIORITY_STEP = 5;
let idSequenceCounter = 0;

export function generateClientId(prefix: string): string {
  idSequenceCounter += 1;
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `${prefix}-${crypto.randomUUID()}`;
  }
  return `${prefix}-${Date.now()}-${idSequenceCounter}`;
}

export function getEphemeralToken(): string {
  if (typeof window !== 'undefined' && typeof window.__ROUTEWARD_TOKEN__ === 'string') {
    return window.__ROUTEWARD_TOKEN__;
  }
  return '';
}

export function buildAuthHeaders(
  extraHeaders?: Record<string, string>,
  tokenOverride?: string
): Record<string, string> {
  const token = tokenOverride !== undefined ? tokenOverride : getEphemeralToken();
  return {
    [UI_CONFIG.TOKEN_HEADER]: token,
    ...(extraHeaders || {})
  };
}

export interface ParsedSseFrame {
  event: string;
  data: string;
}

export function parseSseChunk(buffer: string): {
  events: ParsedSseFrame[];
  remainder: string;
} {
  const normalized = buffer.replace(/\r\n/g, '\n');
  const frames = normalized.split('\n\n');
  const remainder = frames.pop() ?? '';
  const events: ParsedSseFrame[] = [];

  for (const rawFrame of frames) {
    const lines = rawFrame.split('\n');
    let eventName = 'message';
    const dataLines: string[] = [];

    for (const line of lines) {
      if (!line || line.startsWith(':')) {
        continue;
      }
      if (line.startsWith('event:')) {
        eventName = line.slice('event:'.length).trim();
      } else if (line.startsWith('data:')) {
        dataLines.push(line.slice('data:'.length).trim());
      }
    }

    if (dataLines.length > 0) {
      events.push({
        event: eventName,
        data: dataLines.join('\n')
      });
    }
  }

  return { events, remainder };
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

function createInitialProfile(): ProfileConfig {
  const base = JSON.parse(JSON.stringify(DEFAULT_PROFILE_DATA)) as ProfileConfig;
  base.proxies = base.proxies.map((p) => ({
    ...p,
    auth: p.auth
      ? {
          username: p.auth.username,
          hasPassword: Boolean(p.auth.hasPassword || p.auth.password)
        }
      : null
  }));
  return base;
}

function createInitialDiagnostics(profile: ProfileConfig): SystemDiagnostics {
  const net = SYSTEM_CONSTANTS.network;
  const savedLocale =
    typeof window !== 'undefined'
      ? window.localStorage.getItem(UI_CONFIG.STORAGE_KEYS.LOCALE) ||
        UI_CONFIG.DEFAULT_LOCALE
      : UI_CONFIG.DEFAULT_LOCALE;
  return {
    daemonConnected: false,
    running: false,
    osName: 'WINDOWS / LINUX',
    interceptionMode: profile.interceptionMode,
    elevatedPrivileges: false,
    relayTcpEndpoint: `${net.localBindHost}:${net.defaultRelayTcpPort}`,
    relayHttpEndpoint: `${net.localBindHost}:${net.defaultRelayHttpPort}`,
    dnsEndpoint: `${net.localBindHost}:${net.defaultDnsListenPort}`,
    fakeIpCidr: profile.dnsConfig.fakeIpCidr,
    activeLocale: savedLocale
  };
}

function createInitialTelemetry(): TelemetrySnapshot {
  return {
    activeConnections: 0,
    downloadBytesPerSec: 0,
    uploadBytesPerSec: 0,
    totalRxBytes: 0,
    totalTxBytes: 0,
    proxiedCount: 0,
    directCount: 0,
    blockedCount: 0,
    bandwidthHistory: [],
    topTalkers: []
  };
}

export class RouteWardClientService {
  private profile: ProfileConfig;
  private diagnostics: SystemDiagnostics;
  private telemetry: TelemetrySnapshot;
  private connections: TrackedConnection[] = [];
  private logs: LogEntry[] = [];
  private fakeIps: FakeIpEntry[] = [];
  private listeners = new Set<() => void>();
  private streamRunning = false;

  constructor() {
    this.profile = createInitialProfile();
    this.diagnostics = createInitialDiagnostics(this.profile);
    this.telemetry = createInitialTelemetry();
  }

  public subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notifyListeners(): void {
    for (const listener of this.listeners) {
      listener();
    }
  }

  public applyFullState(state: DaemonFullState): void {
    this.profile = state.profile;
    this.diagnostics = {
      ...state.diagnostics,
      running: state.diagnostics.daemonConnected && state.diagnostics.running
    };
    if (!state.diagnostics.daemonConnected) {
      this.telemetry = {
        ...state.telemetry,
        activeConnections: 0,
        downloadBytesPerSec: 0,
        uploadBytesPerSec: 0
      };
      this.connections = state.connections.map((c) =>
        c.status === 'active' ? { ...c, status: 'closed' } : c
      );
    } else {
      this.telemetry = state.telemetry;
      this.connections = state.connections;
    }
    this.logs = state.logs;
    this.fakeIps = state.fakeIps;
    this.notifyListeners();
  }

  public markDisconnectedState(): void {
    this.diagnostics = {
      ...this.diagnostics,
      daemonConnected: false,
      running: false
    };
    this.telemetry = {
      ...this.telemetry,
      activeConnections: 0,
      downloadBytesPerSec: 0,
      uploadBytesPerSec: 0
    };
    this.connections = this.connections.map((c) =>
      c.status === 'active' ? { ...c, status: 'closed' } : c
    );
    this.notifyListeners();
  }

  public applyStreamEvent(event: IpcStreamEvent): boolean {
    if (event.kind === 'resync') {
      return true;
    }
    this.applyTelemetryPayload(event.payload);
    this.notifyListeners();
    return false;
  }

  private applyTelemetryPayload(payload: TelemetryEventPayload): void {
    switch (payload.type) {
      case 'telemetry': {
        this.telemetry = payload.data;
        break;
      }
      case 'connection_updated': {
        const updated = payload.data;
        const idx = this.connections.findIndex((c) => c.id === updated.id);
        if (idx >= 0) {
          this.connections = [
            ...this.connections.slice(0, idx),
            updated,
            ...this.connections.slice(idx + 1)
          ];
        } else {
          this.connections = [updated, ...this.connections];
        }
        this.telemetry = {
          ...this.telemetry,
          topTalkers: this.computeTopTalkers()
        };
        break;
      }
      case 'connections_cleared': {
        this.connections = this.connections.filter((c) => c.status === 'active');
        break;
      }
      case 'log': {
        this.logs = [
          payload.data,
          ...this.logs.slice(
            0,
            SYSTEM_CONSTANTS.telemetry.maxLogRingBufferEntries - 1
          )
        ];
        break;
      }
      case 'logs_cleared': {
        this.logs = [];
        break;
      }
    }
  }

  private computeTopTalkers(): ProcessTrafficSummary[] {
    const map = new Map<string, ProcessTrafficSummary>();
    for (const c of this.connections) {
      const existing = map.get(c.processName) || {
        processName: c.processName,
        activeSockets: 0,
        totalConnections: 0,
        rxBytes: 0,
        txBytes: 0
      };
      existing.totalConnections += 1;
      if (c.status === 'active') {
        existing.activeSockets += 1;
      }
      existing.rxBytes += c.rxBytes;
      existing.txBytes += c.txBytes;
      map.set(c.processName, existing);
    }
    return Array.from(map.values()).sort(
      (a, b) => b.rxBytes + b.txBytes - (a.rxBytes + a.txBytes)
    );
  }

  private async requestJson<T>(
    url: string,
    method: 'GET' | 'POST' = 'GET',
    body?: unknown
  ): Promise<T> {
    const headers = buildAuthHeaders(
      body !== undefined ? { 'Content-Type': 'application/json' } : undefined
    );
    const response = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return (await response.json()) as T;
  }

  public async fetchState(): Promise<DaemonFullState> {
    try {
      const state = await this.requestJson<DaemonFullState>(
        UI_CONFIG.API_ENDPOINTS.STATE,
        'GET'
      );
      this.applyFullState(state);
      return state;
    } catch {
      this.markDisconnectedState();
      return {
        diagnostics: this.diagnostics,
        profile: this.profile,
        telemetry: this.telemetry,
        connections: this.connections,
        logs: this.logs,
        fakeIps: this.fakeIps
      };
    }
  }

  public startRealtimeStream(abortSignal?: AbortSignal): void {
    if (this.streamRunning) {
      return;
    }
    this.streamRunning = true;

    const runLoop = async () => {
      while (!abortSignal?.aborted) {
        await this.fetchState();
        if (abortSignal?.aborted) {
          break;
        }

        try {
          const response = await fetch(UI_CONFIG.API_ENDPOINTS.EVENTS, {
            method: 'GET',
            headers: buildAuthHeaders({ Accept: 'text/event-stream' }),
            signal: abortSignal
          });

          if (!response.ok || !response.body) {
            this.markDisconnectedState();
          } else {
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            while (!abortSignal?.aborted) {
              const { value, done } = await reader.read();
              if (done) {
                break;
              }
              buffer += decoder.decode(value, { stream: true });
              const parsed = parseSseChunk(buffer);
              buffer = parsed.remainder;

              for (const frame of parsed.events) {
                if (frame.event === 'resync') {
                  await this.fetchState();
                  continue;
                }
                try {
                  const streamEv = JSON.parse(frame.data) as IpcStreamEvent;
                  if (this.applyStreamEvent(streamEv)) {
                    await this.fetchState();
                  }
                } catch {
                  // Ignore malformed frame
                }
              }
            }
          }
        } catch {
          if (!abortSignal?.aborted) {
            this.markDisconnectedState();
          }
        }

        if (abortSignal?.aborted) {
          break;
        }
        await new Promise((resolve) =>
          window.setTimeout(resolve, UI_CONFIG.SSE_RECONNECT_DELAY_MS)
        );
      }
      this.streamRunning = false;
    };

    void runLoop();
  }

  public getProfile(): ProfileConfig {
    return this.profile;
  }

  public getDiagnostics(): SystemDiagnostics {
    return this.diagnostics;
  }

  public getTelemetry(): TelemetrySnapshot {
    return this.telemetry;
  }

  public listConnections(): TrackedConnection[] {
    return this.connections;
  }

  public listFakeIps(): FakeIpEntry[] {
    return this.fakeIps;
  }

  public listLogs(): LogEntry[] {
    return this.logs;
  }

  public async toggleEngine(start: boolean): Promise<SystemDiagnostics> {
    try {
      const diag = await this.requestJson<SystemDiagnostics>(
        UI_CONFIG.API_ENDPOINTS.ENGINE_TOGGLE,
        'POST',
        { start }
      );
      this.diagnostics = diag;
      await this.fetchState();
    } catch {
      this.markDisconnectedState();
    }
    return this.diagnostics;
  }

  public async setInterceptionMode(
    mode: InterceptionMode
  ): Promise<SystemDiagnostics> {
    try {
      const diag = await this.requestJson<SystemDiagnostics>(
        UI_CONFIG.API_ENDPOINTS.ENGINE_MODE,
        'POST',
        { mode }
      );
      this.diagnostics = diag;
      this.profile = { ...this.profile, interceptionMode: mode };
      this.notifyListeners();
    } catch {
      this.markDisconnectedState();
    }
    return this.diagnostics;
  }

  public async updateSecurityPolicy(
    partial: Partial<SecurityPolicyConfig>
  ): Promise<ProfileConfig> {
    const updatedProfile: ProfileConfig = {
      ...this.profile,
      securityPolicy: {
        killSwitchEnabled: true,
        blockUdpOnTcpOnlyProxy: true,
        strictDnsNoLocalFallback: true,
        ...(this.profile.securityPolicy || {}),
        ...partial
      }
    };
    return this.replaceProfile(updatedProfile);
  }

  public async replaceProfile(
    newProfile: ProfileConfig
  ): Promise<ProfileConfig> {
    const sanitized: ProfileConfig = {
      ...newProfile,
      proxies: newProfile.proxies.map(sanitizeProxyNodeForWrite)
    };
    try {
      const saved = await this.requestJson<ProfileConfig>(
        UI_CONFIG.API_ENDPOINTS.PROFILE_REPLACE,
        'POST',
        sanitized
      );
      this.profile = saved;
      this.notifyListeners();
    } catch {
      this.markDisconnectedState();
    }
    return this.profile;
  }

  public async importProfileJson(jsonText: string): Promise<ProfileConfig> {
    const parsed = JSON.parse(jsonText) as ProfileConfig;
    return this.replaceProfile(parsed);
  }

  public exportProfileJson(): string {
    const redacted: ProfileConfig = {
      ...this.profile,
      proxies: this.profile.proxies.map((p) => ({
        ...p,
        auth: p.auth
          ? {
              username: p.auth.username,
              hasPassword: Boolean(p.auth.hasPassword)
            }
          : null
      }))
    };
    return JSON.stringify(redacted, null, 2);
  }

  public async terminateConnection(
    connectionId: string
  ): Promise<TrackedConnection[]> {
    try {
      await this.requestJson<{ terminated: boolean }>(
        UI_CONFIG.API_ENDPOINTS.CONNECTIONS_TERMINATE,
        'POST',
        { connectionId }
      );
      await this.fetchState();
    } catch {
      this.markDisconnectedState();
    }
    return this.connections;
  }

  public async clearClosedConnections(): Promise<TrackedConnection[]> {
    try {
      await this.requestJson<{ ok: boolean }>(
        UI_CONFIG.API_ENDPOINTS.CONNECTIONS_CLEAR,
        'POST',
        {}
      );
      await this.fetchState();
    } catch {
      this.markDisconnectedState();
    }
    return this.connections;
  }

  public async evaluateRule(
    req: ConnectionRequest
  ): Promise<RuleEvaluationResult | null> {
    try {
      return await this.requestJson<RuleEvaluationResult>(
        UI_CONFIG.API_ENDPOINTS.RULES_EVALUATE,
        'POST',
        req
      );
    } catch {
      this.markDisconnectedState();
      return null;
    }
  }

  public async testProxy(proxyId: string): Promise<ProxyHealthReport | null> {
    try {
      const report = await this.requestJson<ProxyHealthReport>(
        UI_CONFIG.API_ENDPOINTS.PROXIES_TEST,
        'POST',
        { proxyId }
      );
      await this.fetchState();
      return report;
    } catch {
      this.markDisconnectedState();
      return null;
    }
  }

  public async testAllProxies(): Promise<ProxyHealthReport[]> {
    try {
      const reports = await this.requestJson<ProxyHealthReport[]>(
        UI_CONFIG.API_ENDPOINTS.PROXIES_TEST_ALL,
        'POST',
        {}
      );
      await this.fetchState();
      return reports;
    } catch {
      this.markDisconnectedState();
      return [];
    }
  }

  public async upsertProxy(node: ProxyNode): Promise<ProfileConfig> {
    const payload = sanitizeProxyNodeForWrite(node);
    try {
      const updated = await this.requestJson<ProfileConfig>(
        UI_CONFIG.API_ENDPOINTS.PROXIES_UPSERT,
        'POST',
        payload
      );
      this.profile = updated;
      this.notifyListeners();
    } catch {
      this.markDisconnectedState();
    }
    return this.profile;
  }

  public async removeProxy(proxyId: string): Promise<ProfileConfig> {
    try {
      const updated = await this.requestJson<ProfileConfig>(
        UI_CONFIG.API_ENDPOINTS.PROXIES_REMOVE,
        'POST',
        { proxyId }
      );
      this.profile = updated;
      this.notifyListeners();
    } catch {
      this.markDisconnectedState();
    }
    return this.profile;
  }

  public async importProxyUris(rawText: string): Promise<number> {
    let imported = 0;
    const normalizedText = this.tryDecodeBase64Subscription(rawText);
    const lines = normalizedText
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));

    for (const line of lines) {
      const parsed = this.parseSingleProxyUri(line);
      if (parsed) {
        await this.upsertProxy(parsed);
        imported += 1;
      }
    }
    return imported;
  }

  private tryDecodeBase64Subscription(raw: string): string {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.includes('://')) {
      return raw;
    }
    try {
      const compact = trimmed.replace(/\s+/g, '');
      const decoded = window.atob(compact);
      if (decoded.includes('://')) {
        return decoded;
      }
    } catch {
      // Not a Base64 subscription payload
    }
    return raw;
  }

  public async scanRealOsSockets(): Promise<TrackedConnection[]> {
    try {
      const osConns = await this.requestJson<TrackedConnection[]>(
        UI_CONFIG.API_ENDPOINTS.SCAN_OS,
        'POST',
        {}
      );
      await this.fetchState();
      return osConns;
    } catch {
      this.markDisconnectedState();
      return this.connections;
    }
  }

  public async setSystemProxy(enabled: boolean): Promise<boolean> {
    try {
      await this.requestJson<unknown>(
        UI_CONFIG.API_ENDPOINTS.SYSTEM_PROXY,
        'POST',
        { enabled }
      );
      await this.fetchState();
      return enabled;
    } catch {
      return false;
    }
  }

  public async launchProcessWithProxy(
    executable: string,
    args: string[]
  ): Promise<boolean> {
    try {
      await this.requestJson<unknown>(
        UI_CONFIG.API_ENDPOINTS.LAUNCH_PROCESS,
        'POST',
        { executable, args }
      );
      await this.fetchState();
      return true;
    } catch {
      return false;
    }
  }

  public formatProxyUri(node: ProxyNode): string {
    const scheme = node.protocol;
    const authPart =
      node.auth && node.auth.username
        ? `${encodeURIComponent(node.auth.username)}@`
        : '';
    const queryPart = node.sni ? `?sni=${encodeURIComponent(node.sni)}` : '';
    const hashPart = `#${encodeURIComponent(node.name)}`;
    return `${scheme}://${authPart}${node.host}:${node.port}${queryPart}${hashPart}`;
  }

  private parseSingleProxyUri(uri: string): ProxyNode | null {
    const match = uri.match(/^([a-zA-Z0-9]+):\/\/([^?#]+)(\?[^#]*)?(#.*)?$/);
    if (!match) return null;
    const rawScheme = match[1].toLowerCase();
    const authority = match[2];
    const query = match[3] || '';
    const fragment = match[4] ? decodeURIComponent(match[4].slice(1)) : '';

    const protocolMap: Record<string, ProxyProtocol> = {
      socks5: 'socks5',
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

    const colonIdx = hostPort.lastIndexOf(':');
    if (colonIdx <= 0) return null;
    const host = hostPort.slice(0, colonIdx);
    const port = Number(hostPort.slice(colonIdx + 1).replace(/\/$/, ''));
    if (!host || Number.isNaN(port) || port <= 0) return null;

    let auth: ProxyNode['auth'] = null;
    if (userInfo) {
      const [u, p] = userInfo.split(':');
      const decodedPass = decodeURIComponent(p || '');
      auth = {
        username: decodeURIComponent(u || ''),
        ...(decodedPass ? { password: decodedPass, hasPassword: true } : { hasPassword: false })
      };
    }

    const params = new URLSearchParams(query.replace(/^\?/, ''));
    const sni = params.get('sni');
    const tls = protocol === 'https' || Boolean(sni);

    return {
      id: generateClientId('proxy'),
      name: fragment || `${protocol.toUpperCase()} ${host}:${port}`,
      protocol,
      host,
      port,
      auth,
      udpEnabled: protocol === 'socks5',
      tls,
      sni,
      enabled: true,
      lastLatencyMs: null,
      exitIp: null
    };
  }

  public async upsertChain(chain: ProxyChain): Promise<ProfileConfig> {
    try {
      const updated = await this.requestJson<ProfileConfig>(
        UI_CONFIG.API_ENDPOINTS.CHAINS_UPSERT,
        'POST',
        chain
      );
      this.profile = updated;
      this.notifyListeners();
    } catch {
      this.markDisconnectedState();
    }
    return this.profile;
  }

  public async removeChain(chainId: string): Promise<ProfileConfig> {
    try {
      const updated = await this.requestJson<ProfileConfig>(
        UI_CONFIG.API_ENDPOINTS.CHAINS_REMOVE,
        'POST',
        { chainId }
      );
      this.profile = updated;
      this.notifyListeners();
    } catch {
      this.markDisconnectedState();
    }
    return this.profile;
  }

  public async upsertRule(rule: RoutingRule): Promise<ProfileConfig> {
    try {
      const updated = await this.requestJson<ProfileConfig>(
        UI_CONFIG.API_ENDPOINTS.RULES_UPSERT,
        'POST',
        rule
      );
      this.profile = updated;
      this.notifyListeners();
    } catch {
      this.markDisconnectedState();
    }
    return this.profile;
  }

  public async toggleRuleEnabled(ruleId: string): Promise<ProfileConfig> {
    const target = this.profile.rules.find((r) => r.id === ruleId);
    if (!target) {
      return this.profile;
    }
    return this.upsertRule({ ...target, enabled: !target.enabled });
  }

  public async reorderRulePriority(
    ruleId: string,
    direction: 'up' | 'down'
  ): Promise<ProfileConfig> {
    const sorted = [...this.profile.rules].sort(
      (a, b) => a.priority - b.priority
    );
    const idx = sorted.findIndex((r) => r.id === ruleId);
    if (idx < 0) {
      return this.profile;
    }

    const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
    if (swapIdx >= 0 && swapIdx < sorted.length) {
      const current = { ...sorted[idx] };
      const neighbor = { ...sorted[swapIdx] };
      if (current.priority === neighbor.priority) {
        current.priority =
          direction === 'up'
            ? Math.max(1, neighbor.priority - PRIORITY_STEP)
            : neighbor.priority + PRIORITY_STEP;
      } else {
        const temp = current.priority;
        current.priority = neighbor.priority;
        neighbor.priority = temp;
      }
      sorted[idx] = current;
      sorted[swapIdx] = neighbor;
      sorted.sort((a, b) => a.priority - b.priority);
      return this.replaceProfile({ ...this.profile, rules: sorted });
    }
    return this.profile;
  }

  public async removeRule(ruleId: string): Promise<ProfileConfig> {
    try {
      const updated = await this.requestJson<ProfileConfig>(
        UI_CONFIG.API_ENDPOINTS.RULES_REMOVE,
        'POST',
        { ruleId }
      );
      this.profile = updated;
      this.notifyListeners();
    } catch {
      this.markDisconnectedState();
    }
    return this.profile;
  }

  public async allocateFakeIp(domain: string): Promise<string | null> {
    const clean = domain.trim().toLowerCase();
    if (!clean) return null;
    try {
      const res = await this.requestJson<{ fakeIp: string | null }>(
        UI_CONFIG.API_ENDPOINTS.DNS_ALLOCATE,
        'POST',
        { domain: clean }
      );
      await this.fetchState();
      return res.fakeIp;
    } catch {
      this.markDisconnectedState();
      return null;
    }
  }

  public async flushFakeIps(): Promise<void> {
    try {
      await this.requestJson<{ ok: boolean }>(
        UI_CONFIG.API_ENDPOINTS.DNS_FLUSH,
        'POST',
        {}
      );
      await this.fetchState();
    } catch {
      this.markDisconnectedState();
    }
  }

  public async clearLogs(): Promise<void> {
    try {
      await this.requestJson<{ ok: boolean }>(
        UI_CONFIG.API_ENDPOINTS.LOGS_CLEAR,
        'POST',
        {}
      );
      await this.fetchState();
    } catch {
      this.markDisconnectedState();
    }
  }
}

export const routewardClient = new RouteWardClientService();

export function formatBytes(bytes: number): string {
  if (bytes <= 0) return `0 ${UI_CONFIG.BYTE_UNITS[0]}`;
  const i = Math.min(
    UI_CONFIG.BYTE_UNITS.length - 1,
    Math.floor(Math.log(bytes) / Math.log(UI_CONFIG.BYTE_STEP))
  );
  const value = bytes / Math.pow(UI_CONFIG.BYTE_STEP, i);
  return `${value.toFixed(i === 0 ? 0 : 1)} ${UI_CONFIG.BYTE_UNITS[i]}`;
}
