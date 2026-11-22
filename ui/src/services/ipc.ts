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
  buildDefaultPacUrl,
  DEFAULT_PROFILE_DATA,
  SYSTEM_CONSTANTS,
  UI_CONFIG
} from '../config/constants';
import {
  AutostartStatus,
  ConnectionRequest,
  CurrentNetworkInfo,
  DaemonFullState,
  DetectedProxyCandidate,
  FakeIpEntry,
  FoxyProxyImportResult,
  InterceptionMode,
  IpcStreamEvent,
  LogEntry,
  PacStatus,
  ProcessTrafficSummary,
  ProfileConfig,
  ProfileSummary,
  ProxyChain,
  ProxyHealthReport,
  ProxyNode,
  RoutingRule,
  RuleEvaluationResult,
  SecurityPolicyConfig,
  SystemApplicationEntry,
  SystemDiagnostics,
  TelemetryEventPayload,
  TelemetrySnapshot,
  TrackedConnection
} from '../types/routeward';
import { ParsedSseFrame, parseSseChunk, runRealtimeSseLoop } from './sse';
import { detectInitialLocale } from './locale';
import {
  formatProxyUri as formatProxyUriHelper,
  generateClientId,
  parseSingleProxyUri as parseSingleProxyUriHelper,
  sanitizeProxyNodeForWrite
} from './uri';

export {
  formatProxyUriHelper as formatProxyUri,
  generateClientId,
  parseSingleProxyUriHelper as parseSingleProxyUri,
  parseSseChunk,
  sanitizeProxyNodeForWrite,
  type ParsedSseFrame
};

/** HTTP status used for a request the daemon understood but could not apply. */
const HTTP_STATUS_CONFLICT = 409;

export class HttpResponseError extends Error {
  public readonly status: number;
  public readonly errorKey?: string;

  constructor(status: number, message: string, errorKey?: string) {
    super(message);
    this.name = 'HttpResponseError';
    this.status = status;
    this.errorKey = errorKey;
  }
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
  const savedLocale = detectInitialLocale();
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
    activeLocale: savedLocale,
    pausedUntilEpochMs: null,
    autoStartErrorKey: null
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

/**
 * Combines the request timeout with an optional caller signal (AbortSignal.any when available).
 * `cleanup` detaches the listeners added to the caller signal by the fallback path, so a
 * long-lived stream signal does not accumulate one listener per request.
 */
function buildRequestSignal(
  timeoutMs: number,
  externalSignal?: AbortSignal
): { signal: AbortSignal | undefined; cleanup: () => void } {
  const noop = () => {};
  const timeoutSignal =
    typeof AbortSignal !== 'undefined' &&
    typeof AbortSignal.timeout === 'function'
      ? AbortSignal.timeout(timeoutMs)
      : undefined;
  if (!externalSignal) {
    return { signal: timeoutSignal, cleanup: noop };
  }
  if (!timeoutSignal) {
    return { signal: externalSignal, cleanup: noop };
  }
  if (typeof AbortSignal.any === 'function') {
    return {
      signal: AbortSignal.any([externalSignal, timeoutSignal]),
      cleanup: noop
    };
  }
  const combined = new AbortController();
  const abort = () => combined.abort();
  if (externalSignal.aborted || timeoutSignal.aborted) {
    abort();
    return { signal: combined.signal, cleanup: noop };
  }
  externalSignal.addEventListener('abort', abort);
  timeoutSignal.addEventListener('abort', abort);
  return {
    signal: combined.signal,
    cleanup: () => {
      externalSignal.removeEventListener('abort', abort);
      timeoutSignal.removeEventListener('abort', abort);
    }
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
  private activeStreamSignal: AbortSignal | null = null;
  /** Sequence of the latest state request issued; responses older than the last applied one are dropped. */
  private stateRequestSeq = 0;
  private lastAppliedStateSeq = 0;
  private pendingNotifyTimer: ReturnType<typeof setTimeout> | null = null;

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
    if (this.pendingNotifyTimer !== null) {
      clearTimeout(this.pendingNotifyTimer);
      this.pendingNotifyTimer = null;
    }
    for (const listener of this.listeners) {
      listener();
    }
  }

  /**
   * Coalesces notifications triggered by SSE bursts: at most one listener pass per
   * `STREAM_NOTIFY_COALESCE_MS`, so a burst of events costs a single UI render.
   */
  private scheduleNotifyListeners(): void {
    if (this.pendingNotifyTimer !== null) {
      return;
    }
    this.pendingNotifyTimer = setTimeout(() => {
      this.pendingNotifyTimer = null;
      for (const listener of this.listeners) {
        listener();
      }
    }, UI_CONFIG.STREAM_NOTIFY_COALESCE_MS);
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
    if (event.streamType === 'resync') {
      return true;
    }
    if (event.streamType === 'event' && event.payload) {
      const wasDisconnected = !this.diagnostics.daemonConnected;
      this.applyTelemetryPayload(event.payload);
      this.scheduleNotifyListeners();
      return wasDisconnected;
    }
    return false;
  }

  private applyTelemetryPayload(payload: TelemetryEventPayload): void {
    switch (payload.event) {
      case 'telemetry': {
        this.telemetry = payload.data;
        break;
      }
      case 'connectionUpdated': {
        const updated = payload.data;
        const idx = this.connections.findIndex((c) => c.id === updated.id);
        const isNew = idx < 0;
        if (idx >= 0) {
          this.connections = [
            ...this.connections.slice(0, idx),
            updated,
            ...this.connections.slice(idx + 1)
          ];
        } else {
          this.connections = this.trimConnectionsCache([
            updated,
            ...this.connections
          ]);
        }
        const activeCount = this.connections.filter(
          (c) => c.status === 'active'
        ).length;
        let proxiedCount = this.telemetry.proxiedCount;
        let directCount = this.telemetry.directCount;
        let blockedCount = this.telemetry.blockedCount;
        if (isNew) {
          if (updated.status === 'blocked') {
            blockedCount += 1;
          } else if (updated.routeLabel === 'DIRECT') {
            directCount += 1;
          } else {
            proxiedCount += 1;
          }
        }
        this.telemetry = {
          ...this.telemetry,
          activeConnections: activeCount,
          proxiedCount,
          directCount,
          blockedCount,
          topTalkers: this.computeTopTalkers()
        };
        break;
      }
      case 'connectionsCleared': {
        this.connections = this.connections.filter((c) => c.status === 'active');
        this.telemetry = {
          ...this.telemetry,
          activeConnections: this.connections.length,
          topTalkers: this.computeTopTalkers()
        };
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
      case 'logsCleared': {
        this.logs = [];
        break;
      }
    }
  }

  private trimConnectionsCache(
    list: TrackedConnection[]
  ): TrackedConnection[] {
    const cap = Math.max(
      1,
      SYSTEM_CONSTANTS.telemetry.maxConnectionHistoryEntries ??
        UI_CONFIG.CONNECTION_CACHE_FALLBACK_ENTRIES
    );
    if (list.length <= cap) {
      return list;
    }
    const result = [...list];
    while (result.length > cap) {
      let removeIdx = -1;
      for (let i = result.length - 1; i >= 0; i -= 1) {
        if (result[i].status !== 'active') {
          removeIdx = i;
          break;
        }
      }
      if (removeIdx < 0) {
        break;
      }
      result.splice(removeIdx, 1);
    }
    return result;
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

  /**
   * Network-level failures flip the client to the disconnected state. The error is then
   * rethrown so a mutation never reports success to the caller: an HTTP error answer means the
   * bridge is reachable, and an unreachable bridge means the change was not applied either.
   * Read helpers that return a harmless fallback pass `rethrowNetworkError = false`.
   */
  private handleRequestFailure(err: unknown, rethrowNetworkError = true): void {
    if (err instanceof HttpResponseError) {
      throw err;
    }
    this.markDisconnectedState();
    if (rethrowNetworkError) {
      throw err;
    }
  }

  private async requestJson<T>(
    url: string,
    method: 'GET' | 'POST' = 'GET',
    body?: unknown,
    timeoutMs: number = UI_CONFIG.REQUEST_TIMEOUT_MS,
    externalSignal?: AbortSignal
  ): Promise<T> {
    const headers = buildAuthHeaders(
      body !== undefined ? { 'Content-Type': 'application/json' } : undefined
    );
    if (method !== 'GET') {
      this.lastAppliedStateSeq = ++this.stateRequestSeq;
    }
    const { signal, cleanup } = buildRequestSignal(timeoutMs, externalSignal);
    try {
      return await this.sendJsonRequest<T>(url, method, headers, body, signal);
    } finally {
      cleanup();
      if (method !== 'GET') {
        // The mutation response is about to be applied locally: discard any older in-flight
        // state poll so it cannot briefly revert the new state.
        this.lastAppliedStateSeq = ++this.stateRequestSeq;
      }
    }
  }

  private async sendJsonRequest<T>(
    url: string,
    method: 'GET' | 'POST',
    headers: Record<string, string>,
    body: unknown,
    signal: AbortSignal | undefined
  ): Promise<T> {
    const response = await fetch(url, {
      method,
      headers,
      cache: 'no-store',
      signal,
      body: body !== undefined ? JSON.stringify(body) : undefined
    });
    if (!response.ok) {
      let detail = `HTTP ${response.status}`;
      let errorKey: string | undefined;
      try {
        const errBody = (await response.json()) as {
          error?: unknown;
          errorKey?: unknown;
        };
        if (errBody && typeof errBody.error === 'string' && errBody.error.trim()) {
          detail = errBody.error;
        }
        if (
          errBody &&
          typeof errBody.errorKey === 'string' &&
          errBody.errorKey.trim()
        ) {
          errorKey = errBody.errorKey;
        }
      } catch {
        // Response did not contain a structured JSON error payload
      }
      throw new HttpResponseError(response.status, detail, errorKey);
    }
    return (await response.json()) as T;
  }

  public async fetchState(): Promise<DaemonFullState> {
    const seq = ++this.stateRequestSeq;
    try {
      const state = await this.requestJson<DaemonFullState>(
        UI_CONFIG.API_ENDPOINTS.STATE,
        'GET'
      );
      // A response older than the one already applied must not roll the state back.
      if (seq > this.lastAppliedStateSeq) {
        this.lastAppliedStateSeq = seq;
        this.applyFullState(state);
      }
      return state;
    } catch {
      if (seq > this.lastAppliedStateSeq) {
        this.lastAppliedStateSeq = seq;
        this.markDisconnectedState();
      }
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
    if (this.activeStreamSignal && !this.activeStreamSignal.aborted) {
      return;
    }
    const streamSignal = abortSignal ?? new AbortController().signal;
    this.activeStreamSignal = streamSignal;

    // The SSE stream does not carry engine state: poll it so a start/stop done from the
    // CLI or the tray shows up in the header.
    const stopStatePolling = this.startStatePolling(streamSignal);

    void runRealtimeSseLoop(
      {
        endpoint: UI_CONFIG.API_ENDPOINTS.EVENTS,
        headers: () => buildAuthHeaders({ Accept: 'text/event-stream' }),
        reconnectDelayMs: UI_CONFIG.SSE_RECONNECT_DELAY_MS,
        fetchState: async () => {
          await this.fetchState();
        },
        onDisconnected: () => this.markDisconnectedState(),
        onStreamEvent: (ev) => this.applyStreamEvent(ev)
      },
      streamSignal
    ).finally(() => {
      stopStatePolling();
      if (this.activeStreamSignal === streamSignal) {
        this.activeStreamSignal = null;
      }
    });
  }

  /**
   * Polls the daemon state with a self-rescheduling timer armed only after the previous poll
   * settled (no overlap). Polls are skipped while the document is hidden and resume at once
   * when it becomes visible. Returns a function that stops the poller and releases its listener.
   */
  private startStatePolling(signal: AbortSignal): () => void {
    let timer: ReturnType<typeof setTimeout> | null = null;
    let stopped = false;

    const schedule = () => {
      if (stopped || signal.aborted) {
        return;
      }
      timer = setTimeout(() => {
        void run();
      }, UI_CONFIG.STATE_REFRESH_INTERVAL_MS);
    };
    const run = async () => {
      timer = null;
      if (stopped || signal.aborted) {
        return;
      }
      if (!document.hidden) {
        await this.pollState(signal);
      }
      schedule();
    };
    const onVisibilityChange = () => {
      // Only resume when idle (timer armed): a poll in flight reschedules itself.
      if (!document.hidden && !stopped && timer !== null) {
        clearTimeout(timer);
        void run();
      }
    };
    const stop = () => {
      stopped = true;
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };

    document.addEventListener('visibilitychange', onVisibilityChange);
    signal.addEventListener('abort', stop);
    schedule();
    return stop;
  }

  /**
   * One background state poll. A failure is ignored on purpose: connectivity is owned by the
   * SSE loop. Only the diagnostics and profile are compared before applying (small payloads);
   * telemetry, connections and logs are kept current by the SSE stream, so a poll that finds
   * the same engine state costs no UI render.
   */
  private async pollState(signal: AbortSignal): Promise<void> {
    const seq = ++this.stateRequestSeq;
    let state: DaemonFullState;
    try {
      state = await this.requestJson<DaemonFullState>(
        UI_CONFIG.API_ENDPOINTS.STATE,
        'GET',
        undefined,
        UI_CONFIG.STATE_POLL_TIMEOUT_MS,
        signal
      );
    } catch {
      return;
    }
    if (seq <= this.lastAppliedStateSeq) {
      return;
    }
    const unchanged =
      JSON.stringify(state.diagnostics) === JSON.stringify(this.diagnostics) &&
      JSON.stringify(state.profile) === JSON.stringify(this.profile);
    if (unchanged) {
      return;
    }
    this.lastAppliedStateSeq = seq;
    this.applyFullState(state);
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
      return this.diagnostics;
    } catch (err) {
      this.handleRequestFailure(err);
      if (err instanceof HttpResponseError) {
        throw err;
      }
    }
    return this.diagnostics;
  }

  /**
   * Pauses protection for `seconds`. The daemon owns the deadline and resumes by itself, so the
   * pause survives a closed window; the end time comes back in `pausedUntilEpochMs`.
   */
  public async pauseEngine(seconds: number): Promise<SystemDiagnostics> {
    try {
      const diag = await this.requestJson<SystemDiagnostics>(
        UI_CONFIG.API_ENDPOINTS.ENGINE_PAUSE,
        'POST',
        { seconds }
      );
      this.diagnostics = diag;
      await this.fetchState();
      return this.diagnostics;
    } catch (err) {
      this.handleRequestFailure(err);
      if (err instanceof HttpResponseError) {
        throw err;
      }
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
    } catch (err) {
      this.handleRequestFailure(err);
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
    } catch (err) {
      this.handleRequestFailure(err);
    }
    return this.profile;
  }

  public async importProfileJson(jsonText: string): Promise<ProfileConfig> {
    const parsed = JSON.parse(jsonText) as ProfileConfig;
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      !Array.isArray(parsed.proxies) ||
      !Array.isArray(parsed.rules)
    ) {
      throw new Error('Invalid profile structure');
    }
    const sanitized: ProfileConfig = {
      ...parsed,
      proxies: parsed.proxies.map(sanitizeProxyNodeForWrite)
    };
    try {
      const saved = await this.requestJson<ProfileConfig>(
        UI_CONFIG.API_ENDPOINTS.PROFILE_REPLACE,
        'POST',
        sanitized
      );
      this.profile = saved;
      this.notifyListeners();
      return this.profile;
    } catch (err) {
      this.handleRequestFailure(err);
      throw err;
    }
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
    let terminated = false;
    try {
      const res = await this.requestJson<{ terminated: boolean }>(
        UI_CONFIG.API_ENDPOINTS.CONNECTIONS_TERMINATE,
        'POST',
        { connectionId }
      );
      terminated = res?.terminated === true;
      await this.fetchState();
    } catch (err) {
      this.handleRequestFailure(err);
    }
    if (!terminated) {
      // The daemon answered but there was nothing to terminate (already closed or unknown id).
      throw new HttpResponseError(
        HTTP_STATUS_CONFLICT,
        `Connection ${connectionId} was not terminated`
      );
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
    } catch (err) {
      this.handleRequestFailure(err);
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
    } catch (err) {
      this.handleRequestFailure(err, false);
      return null;
    }
  }

  public async testProxy(proxyId: string): Promise<ProxyHealthReport | null> {
    try {
      const report = await this.requestJson<ProxyHealthReport>(
        UI_CONFIG.API_ENDPOINTS.PROXIES_TEST,
        'POST',
        { proxyId },
        UI_CONFIG.LONG_REQUEST_TIMEOUT_MS
      );
      await this.fetchState();
      return report;
    } catch (err) {
      this.handleRequestFailure(err);
      return null;
    }
  }

  public async testAllProxies(): Promise<ProxyHealthReport[]> {
    try {
      const reports = await this.requestJson<ProxyHealthReport[]>(
        UI_CONFIG.API_ENDPOINTS.PROXIES_TEST_ALL,
        'POST',
        {},
        UI_CONFIG.LONG_REQUEST_TIMEOUT_MS
      );
      await this.fetchState();
      return reports;
    } catch (err) {
      this.handleRequestFailure(err);
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
    } catch (err) {
      this.handleRequestFailure(err);
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
    } catch (err) {
      this.handleRequestFailure(err);
    }
    return this.profile;
  }

  public async setPrimaryProxy(proxyId: string): Promise<ProfileConfig> {
    try {
      const updated = await this.requestJson<ProfileConfig>(
        UI_CONFIG.API_ENDPOINTS.PROXIES_SET_PRIMARY,
        'POST',
        { proxyId }
      );
      this.profile = updated;
      this.notifyListeners();
    } catch (err) {
      this.handleRequestFailure(err);
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

    let firstFailure: HttpResponseError | null = null;
    for (const line of lines) {
      const parsed = this.parseSingleProxyUri(line);
      if (parsed) {
        try {
          await this.upsertProxy(parsed);
          imported += 1;
        } catch (err) {
          if (!(err instanceof HttpResponseError)) {
            throw err;
          }
          firstFailure = firstFailure ?? err;
        }
      }
    }
    if (imported === 0 && firstFailure) {
      throw firstFailure;
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
        {},
        UI_CONFIG.LONG_REQUEST_TIMEOUT_MS
      );
      await this.fetchState();
      return osConns;
    } catch (err) {
      this.handleRequestFailure(err, false);
      return this.connections;
    }
  }

  public async setSystemProxy(enabled: boolean): Promise<boolean> {
    try {
      const confirmed = await this.requestJson<boolean>(
        UI_CONFIG.API_ENDPOINTS.SYSTEM_PROXY,
        'POST',
        { enabled }
      );
      await this.fetchState();
      return Boolean(confirmed);
    } catch (err) {
      this.handleRequestFailure(err);
      throw err;
    }
  }

  public async launchProcessWithProxy(
    executable: string,
    args: string[]
  ): Promise<void> {
    try {
      await this.requestJson<unknown>(
        UI_CONFIG.API_ENDPOINTS.LAUNCH_PROCESS,
        'POST',
        { executable, args }
      );
      await this.fetchState();
    } catch (err) {
      this.handleRequestFailure(err);
      throw err;
    }
  }

  public formatProxyUri(node: ProxyNode): string {
    return formatProxyUriHelper(node);
  }

  public parseSingleProxyUri(uri: string): ProxyNode | null {
    return parseSingleProxyUriHelper(uri);
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
    } catch (err) {
      this.handleRequestFailure(err);
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
    } catch (err) {
      this.handleRequestFailure(err);
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
    } catch (err) {
      this.handleRequestFailure(err);
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
            ? Math.max(1, neighbor.priority - UI_CONFIG.PRIORITY_STEP)
            : neighbor.priority + UI_CONFIG.PRIORITY_STEP;
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
    } catch (err) {
      this.handleRequestFailure(err);
    }
    return this.profile;
  }

  public async allocateFakeIp(domain: string): Promise<string | null> {
    const clean = domain.trim().toLowerCase();
    if (!clean) return null;
    try {
      const res = await this.requestJson<{ allocated: string | null }>(
        UI_CONFIG.API_ENDPOINTS.DNS_ALLOCATE,
        'POST',
        { domain: clean }
      );
      await this.fetchState();
      return res.allocated;
    } catch (err) {
      this.handleRequestFailure(err);
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
    } catch (err) {
      this.handleRequestFailure(err);
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
    } catch (err) {
      this.handleRequestFailure(err);
    }
  }

  public async startDaemon(): Promise<{
    connected: boolean;
    fallbackReasonKey?: string;
  }> {
    const res = await this.requestJson<{
      started: boolean;
      connected: boolean;
      state?: DaemonFullState;
      fallbackReasonKey?: string;
    }>(
      UI_CONFIG.API_ENDPOINTS.DAEMON_START,
      'POST',
      {},
      UI_CONFIG.LONG_REQUEST_TIMEOUT_MS
    );
    if (res.state) {
      this.applyFullState(res.state);
    } else {
      await this.fetchState();
    }
    return {
      connected: this.diagnostics.daemonConnected,
      ...(res.fallbackReasonKey
        ? { fallbackReasonKey: res.fallbackReasonKey }
        : {})
    };
  }

  public async setDesktopLocale(locale: 'fr' | 'en'): Promise<void> {
    try {
      await this.requestJson<{ ok: boolean }>(
        UI_CONFIG.API_ENDPOINTS.LOCALE,
        'POST',
        { locale }
      );
    } catch {
      // Ignore network errors when UI runs standalone outside desktop host
    }
  }

  public async setDesktopTheme(payload: {
    theme: string;
    accent: string;
    isLight: boolean;
    surfaceHex: string;
    textPrimaryHex: string;
    borderHex: string;
  }): Promise<void> {
    try {
      await this.requestJson<{ ok: boolean }>(
        UI_CONFIG.API_ENDPOINTS.THEME,
        'POST',
        payload
      );
    } catch (err) {
      if (err instanceof HttpResponseError) {
        throw err;
      }
      // Ignore network errors when UI runs standalone outside desktop host
    }
  }

  public async getPacStatus(): Promise<PacStatus> {
    const fallbackUrl = buildDefaultPacUrl();
    try {
      return await this.requestJson<PacStatus>(
        UI_CONFIG.API_ENDPOINTS.SYSTEM_PAC,
        'GET'
      );
    } catch {
      return { enabled: false, pacUrl: fallbackUrl };
    }
  }

  public async setSystemPac(enabled: boolean): Promise<PacStatus> {
    return this.requestJson<PacStatus>(
      UI_CONFIG.API_ENDPOINTS.SYSTEM_PAC,
      'POST',
      { enabled }
    );
  }

  public async getSystemProxyStatus(): Promise<AutostartStatus> {
    try {
      return await this.requestJson<AutostartStatus>(
        UI_CONFIG.API_ENDPOINTS.SYSTEM_PROXY,
        'GET'
      );
    } catch {
      return { enabled: false };
    }
  }

  public async getAutostartStatus(): Promise<AutostartStatus> {
    try {
      return await this.requestJson<AutostartStatus>(
        UI_CONFIG.API_ENDPOINTS.SYSTEM_AUTOSTART,
        'GET'
      );
    } catch {
      return { enabled: false };
    }
  }

  public async setAutostart(enabled: boolean): Promise<AutostartStatus> {
    return this.requestJson<AutostartStatus>(
      UI_CONFIG.API_ENDPOINTS.SYSTEM_AUTOSTART,
      'POST',
      { enabled }
    );
  }

  public async listSystemApplications(): Promise<SystemApplicationEntry[]> {
    try {
      return await this.requestJson<SystemApplicationEntry[]>(
        UI_CONFIG.API_ENDPOINTS.SYSTEM_APPS,
        'GET'
      );
    } catch {
      return [];
    }
  }

  public async detectExistingProxies(): Promise<DetectedProxyCandidate[]> {
    try {
      return await this.requestJson<DetectedProxyCandidate[]>(
        UI_CONFIG.API_ENDPOINTS.SYSTEM_DETECT_PROXIES,
        'GET'
      );
    } catch {
      return [];
    }
  }

  /** Like `detectExistingProxies` but lets a failed detection reach the caller. */
  public async detectExistingProxiesStrict(): Promise<DetectedProxyCandidate[]> {
    return this.requestJson<DetectedProxyCandidate[]>(
      UI_CONFIG.API_ENDPOINTS.SYSTEM_DETECT_PROXIES,
      'GET'
    );
  }

  public async getCurrentNetworkInfo(): Promise<CurrentNetworkInfo> {
    try {
      return await this.requestJson<CurrentNetworkInfo>(
        UI_CONFIG.API_ENDPOINTS.SYSTEM_NETWORK_INFO,
        'GET'
      );
    } catch {
      return { networkName: null, kind: 'unknown' };
    }
  }

  public async getDirectIp(): Promise<string | null> {
    try {
      const res = await this.requestJson<{ directIp: string | null }>(
        UI_CONFIG.API_ENDPOINTS.SYSTEM_DIRECT_IP,
        'GET'
      );
      return res.directIp ?? null;
    } catch {
      return null;
    }
  }

  public async importFoxyProxyJson(
    json: string,
    processPatterns: string[] = []
  ): Promise<FoxyProxyImportResult> {
    const result = await this.requestJson<FoxyProxyImportResult>(
      UI_CONFIG.API_ENDPOINTS.IMPORT_FOXYPROXY,
      'POST',
      { json, processPatterns }
    );
    await this.fetchState();
    return result;
  }

  public async listNamedProfiles(): Promise<ProfileSummary[]> {
    try {
      return await this.requestJson<ProfileSummary[]>(
        UI_CONFIG.API_ENDPOINTS.PROFILES_LIST,
        'GET'
      );
    } catch {
      return [];
    }
  }

  public async saveNamedProfile(
    profileId?: string,
    name?: string
  ): Promise<ProfileSummary[]> {
    const list = await this.requestJson<ProfileSummary[]>(
      UI_CONFIG.API_ENDPOINTS.PROFILES_SAVE,
      'POST',
      { profileId, name }
    );
    await this.fetchState();
    return list;
  }

  public async switchNamedProfile(profileId: string): Promise<ProfileConfig> {
    const updated = await this.requestJson<ProfileConfig>(
      UI_CONFIG.API_ENDPOINTS.PROFILES_SWITCH,
      'POST',
      { profileId }
    );
    this.profile = updated;
    this.notifyListeners();
    return updated;
  }

  public async deleteNamedProfile(profileId: string): Promise<ProfileSummary[]> {
    return this.requestJson<ProfileSummary[]>(
      UI_CONFIG.API_ENDPOINTS.PROFILES_DELETE,
      'POST',
      { profileId }
    );
  }
}

export const routewardClient = new RouteWardClientService();

export { formatBytes } from './format';
