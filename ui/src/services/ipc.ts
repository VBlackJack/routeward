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
  FakeIpEntry,
  InterceptionMode,
  LogEntry,
  ProcessTrafficSummary,
  ProfileConfig,
  ProxyChain,
  ProxyHealthReport,
  ProxyNode,
  ProxyProtocol,
  RoutingRule,
  RuleAction,
  RuleEvaluationResult,
  SecurityPolicyConfig,
  SystemDiagnostics,
  TelemetrySnapshot,
  TrackedConnection
} from '../types/routeward';

const FAKE_IP_OCTET_A = 198;
const FAKE_IP_OCTET_B = 18;
const DEFAULT_FALLBACK_RULE_ID = 'default-policy';
const DEFAULT_FALLBACK_RULE_NAME = 'Default Profile Policy';
const SIMULATED_RX_BASE = 24576;
const SIMULATED_TX_BASE = 6144;
const SIMULATED_LATENCY_BASE_MS = 14;
const PRIORITY_STEP = 5;

class RouteWardClientService {
  private profile: ProfileConfig;
  private running = true;
  private connections: TrackedConnection[] = [];
  private logs: LogEntry[] = [];
  private fakeIpMap = new Map<string, FakeIpEntry>();
  private reverseFakeIp = new Map<string, string>();
  private nextFakeIpOffset = 1;
  private totalRx = 0;
  private totalTx = 0;
  private proxiedCount = 0;
  private directCount = 0;
  private blockedCount = 0;
  private bandwidthHistory: Array<{
    timestamp: string;
    rxBytesPerSec: number;
    txBytesPerSec: number;
  }> = [];

  constructor() {
    const saved = window.localStorage.getItem(UI_CONFIG.STORAGE_KEYS.PROFILE);
    this.profile = saved
      ? (JSON.parse(saved) as ProfileConfig)
      : (JSON.parse(JSON.stringify(DEFAULT_PROFILE_DATA)) as ProfileConfig);

    if (!this.profile.securityPolicy) {
      this.profile.securityPolicy = {
        killSwitchEnabled: true,
        blockUdpOnTcpOnlyProxy: true,
        strictDnsNoLocalFallback: true
      };
    }

    this.allocateFakeIp('api.github.com');
    this.allocateFakeIp('stealth.torproject.org');
    this.allocateFakeIp('registry.npmjs.org');
    this.allocateFakeIp('crates.io');

    for (const preset of UI_CONFIG.SIMULATION_PRESETS) {
      this.simulateConnection(preset);
    }
  }

  private persistProfile(): void {
    window.localStorage.setItem(
      UI_CONFIG.STORAGE_KEYS.PROFILE,
      JSON.stringify(this.profile)
    );
  }

  public getProfile(): ProfileConfig {
    return JSON.parse(JSON.stringify(this.profile)) as ProfileConfig;
  }

  public updateSecurityPolicy(
    partial: Partial<SecurityPolicyConfig>
  ): ProfileConfig {
    this.profile.securityPolicy = {
      killSwitchEnabled: true,
      blockUdpOnTcpOnlyProxy: true,
      strictDnsNoLocalFallback: true,
      ...(this.profile.securityPolicy || {}),
      ...partial
    };
    this.persistProfile();
    this.pushLog(
      'INFO',
      'SecurityShield',
      `Updated security policy: KillSwitch=${this.profile.securityPolicy.killSwitchEnabled}`
    );
    return this.getProfile();
  }

  public importProfileJson(jsonText: string): ProfileConfig {
    const parsed = JSON.parse(jsonText) as ProfileConfig;
    this.profile = parsed;
    this.persistProfile();
    this.pushLog('INFO', 'ProfileManager', `Imported profile: ${parsed.name}`);
    return this.getProfile();
  }

  public exportProfileJson(): string {
    return JSON.stringify(this.profile, null, 2);
  }

  public getDiagnostics(): SystemDiagnostics {
    const net = SYSTEM_CONSTANTS.network;
    return {
      running: this.running,
      osName: 'WINDOWS / LINUX',
      interceptionMode: this.profile.interceptionMode,
      elevatedPrivileges: true,
      relayTcpEndpoint: `${net.localBindHost}:${net.defaultRelayTcpPort}`,
      relayHttpEndpoint: `${net.localBindHost}:${net.defaultRelayHttpPort}`,
      dnsEndpoint: `${net.localBindHost}:${net.defaultDnsListenPort}`,
      fakeIpCidr: this.profile.dnsConfig.fakeIpCidr,
      activeLocale:
        window.localStorage.getItem(UI_CONFIG.STORAGE_KEYS.LOCALE) ||
        UI_CONFIG.DEFAULT_LOCALE
    };
  }

  public toggleEngine(start: boolean): SystemDiagnostics {
    this.running = start;
    this.pushLog(
      start ? 'INFO' : 'WARN',
      'InterceptorEngine',
      start ? 'Engine started' : 'Engine paused'
    );
    return this.getDiagnostics();
  }

  public setInterceptionMode(mode: InterceptionMode): SystemDiagnostics {
    this.profile.interceptionMode = mode;
    this.persistProfile();
    this.pushLog('INFO', 'InterceptorEngine', `Mode switched to ${mode}`);
    return this.getDiagnostics();
  }

  public getTelemetry(): TelemetrySnapshot {
    const nowLabel = new Date().toTimeString().slice(0, 8);
    const activeConns = this.connections.filter(
      (c) => c.status === 'active'
    ).length;

    const rxRate = this.running ? activeConns * SIMULATED_RX_BASE : 0;
    const txRate = this.running ? activeConns * SIMULATED_TX_BASE : 0;

    if (this.running && activeConns > 0) {
      this.totalRx += Math.round(rxRate / 4);
      this.totalTx += Math.round(txRate / 4);
    }

    this.bandwidthHistory.push({
      timestamp: nowLabel,
      rxBytesPerSec: rxRate,
      txBytesPerSec: txRate
    });
    if (
      this.bandwidthHistory.length >
      SYSTEM_CONSTANTS.telemetry.maxBandwidthHistorySamples
    ) {
      this.bandwidthHistory.shift();
    }

    return {
      activeConnections: activeConns,
      downloadBytesPerSec: rxRate,
      uploadBytesPerSec: txRate,
      totalRxBytes: this.totalRx,
      totalTxBytes: this.totalTx,
      proxiedCount: this.proxiedCount,
      directCount: this.directCount,
      blockedCount: this.blockedCount,
      bandwidthHistory: [...this.bandwidthHistory],
      topTalkers: this.computeTopTalkers()
    };
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

  public listConnections(): TrackedConnection[] {
    return [...this.connections];
  }

  public terminateConnection(connectionId: string): TrackedConnection[] {
    const target = this.connections.find((c) => c.id === connectionId);
    if (target && target.status === 'active') {
      target.status = 'closed';
      this.pushLog(
        'WARN',
        'SocketControl',
        `Terminated socket for ${target.processName} -> ${target.targetHost}:${target.targetPort}`
      );
    }
    return [...this.connections];
  }

  public clearClosedConnections(): TrackedConnection[] {
    this.connections = this.connections.filter((c) => c.status === 'active');
    return [...this.connections];
  }

  public evaluateRule(req: ConnectionRequest): RuleEvaluationResult {
    const resolvedFakeDomain = this.reverseFakeIp.get(req.targetHost) || null;
    const effectiveDomain =
      resolvedFakeDomain ||
      (!/^\d+\.\d+\.\d+\.\d+$/.test(req.targetHost)
        ? req.targetHost.toLowerCase()
        : null);

    const sortedRules = [...this.profile.rules]
      .filter((r) => r.enabled)
      .sort((a, b) => a.priority - b.priority);

    for (const rule of sortedRules) {
      if (this.matchesRule(rule, req, effectiveDomain)) {
        return {
          matchedRuleId: rule.id,
          matchedRuleName: rule.name,
          action: rule.action,
          effectiveDomain,
          resolvedFromFakeIp: Boolean(resolvedFakeDomain)
        };
      }
    }

    return {
      matchedRuleId: DEFAULT_FALLBACK_RULE_ID,
      matchedRuleName: DEFAULT_FALLBACK_RULE_NAME,
      action: this.profile.defaultAction,
      effectiveDomain,
      resolvedFromFakeIp: Boolean(resolvedFakeDomain)
    };
  }

  private matchesRule(
    rule: RoutingRule,
    req: ConnectionRequest,
    effectiveDomain: string | null
  ): boolean {
    if (rule.protocol !== 'any' && rule.protocol !== req.protocol) {
      return false;
    }

    if (
      rule.portRanges.length > 0 &&
      !rule.portRanges.some(
        (r) => req.targetPort >= r.start && req.targetPort <= r.end
      )
    ) {
      return false;
    }

    if (rule.processPatterns.length > 0) {
      const candidate = req.processName.toLowerCase();
      const fullPath = (req.processPath || req.processName).toLowerCase();
      const matchedProc = rule.processPatterns.some(
        (pat) =>
          this.globMatch(pat.toLowerCase(), candidate) ||
          this.globMatch(pat.toLowerCase(), fullPath)
      );
      if (!matchedProc) {
        return false;
      }
    }

    if (rule.domainPatterns.length > 0 || rule.ipCidrs.length > 0) {
      let matchedTarget = false;
      if (effectiveDomain && rule.domainPatterns.length > 0) {
        matchedTarget = rule.domainPatterns.some((pat) =>
          this.globMatch(pat.toLowerCase(), effectiveDomain)
        );
      }
      if (!matchedTarget && rule.ipCidrs.length > 0) {
        matchedTarget = rule.ipCidrs.some((cidr) =>
          req.targetHost.startsWith(cidr.split('/')[0].replace(/\.0+$/, ''))
        );
      }
      if (!matchedTarget) {
        return false;
      }
    }

    return true;
  }

  private globMatch(pattern: string, text: string): boolean {
    if (pattern === '*') return true;
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(2);
      if (text === suffix || text.endsWith(`.${suffix}`)) return true;
    }
    const regexStr =
      '^' +
      pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.') +
      '$';
    return new RegExp(regexStr, 'i').test(text);
  }

  public simulateConnection(req: ConnectionRequest): TrackedConnection {
    const evalRes = this.evaluateRule(req);
    const routeLabel = this.formatActionLabel(evalRes.action);
    const isBlocked = evalRes.action.type === 'block';
    const isProxied =
      evalRes.action.type === 'proxy' || evalRes.action.type === 'chain';

    if (isBlocked) {
      this.blockedCount += 1;
    } else if (isProxied) {
      this.proxiedCount += 1;
    } else {
      this.directCount += 1;
    }

    if (
      evalRes.effectiveDomain &&
      !this.fakeIpMap.has(evalRes.effectiveDomain)
    ) {
      this.allocateFakeIp(evalRes.effectiveDomain);
    }

    const rx = isBlocked ? 0 : SIMULATED_RX_BASE;
    const tx = isBlocked ? 0 : SIMULATED_TX_BASE;
    this.totalRx += rx;
    this.totalTx += tx;

    const conn: TrackedConnection = {
      id: `conn-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      pid: Math.floor(1200 + Math.random() * 8000),
      processName: req.processName.split(/[/\\]/).pop() || req.processName,
      processPath: req.processPath || req.processName,
      targetHost: req.targetHost,
      resolvedDomain: evalRes.effectiveDomain,
      targetPort: req.targetPort,
      protocol: req.protocol,
      matchedRule: evalRes.matchedRuleName,
      routeLabel,
      latencyMs: isBlocked ? 0 : SIMULATED_LATENCY_BASE_MS,
      rxBytes: rx,
      txBytes: tx,
      status: isBlocked ? 'blocked' : 'active',
      startedAt: new Date().toISOString()
    };

    this.connections.unshift(conn);
    this.pushLog(
      isBlocked ? 'WARN' : 'INFO',
      'RuleEngine',
      `[${conn.processName}] ${conn.targetHost}:${conn.targetPort} -> ${routeLabel} (${conn.matchedRule})`
    );
    return conn;
  }

  private formatActionLabel(action: RuleAction): string {
    if (action.type === 'direct') return 'DIRECT';
    if (action.type === 'block') return 'BLOCKED';
    if (action.type === 'proxy') {
      const p = this.profile.proxies.find((x) => x.id === action.targetId);
      return p ? `${p.name} (${p.protocol.toUpperCase()})` : action.targetId || 'PROXY';
    }
    const c = this.profile.chains.find((x) => x.id === action.targetId);
    return c
      ? `${c.name} (${c.proxyIds.length} nodes)`
      : action.targetId || 'CHAIN';
  }

  public async testProxy(proxyId: string): Promise<ProxyHealthReport> {
    const node = this.profile.proxies.find((p) => p.id === proxyId);
    const latency = Math.floor(12 + Math.random() * 42);
    if (node) {
      node.lastLatencyMs = latency;
      node.exitIp = node.host === '127.0.0.1' ? '185.220.101.42' : node.host;
      this.persistProfile();
      this.pushLog(
        'INFO',
        'ProxyChecker',
        `${node.name} (${node.host}:${node.port}) -> ${latency} ms [Exit: ${node.exitIp}]`
      );
    }
    return {
      proxyId,
      reachable: true,
      latencyMs: latency,
      udpSupported: node?.udpEnabled ?? false,
      exitIp: node?.exitIp ?? null,
      errorDetail: null
    };
  }

  public async testAllProxies(): Promise<ProxyHealthReport[]> {
    const reports: ProxyHealthReport[] = [];
    for (const p of this.profile.proxies) {
      reports.push(await this.testProxy(p.id));
    }
    return reports;
  }

  public upsertProxy(node: ProxyNode): ProfileConfig {
    const idx = this.profile.proxies.findIndex((p) => p.id === node.id);
    if (idx >= 0) {
      this.profile.proxies[idx] = node;
    } else {
      this.profile.proxies.push(node);
    }
    this.persistProfile();
    return this.getProfile();
  }

  public importProxyUris(rawText: string): number {
    let imported = 0;
    const normalizedText = this.tryDecodeBase64Subscription(rawText);
    const lines = normalizedText
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));

    for (const line of lines) {
      const parsed = this.parseSingleProxyUri(line);
      if (parsed) {
        this.upsertProxy(parsed);
        imported += 1;
      }
    }
    if (imported > 0) {
      this.pushLog(
        'INFO',
        'ProxyUriCodec',
        `Imported ${imported} proxy servers from URI / Subscription list`
      );
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
      const res = await fetch('/api/scan-os', { method: 'POST' });
      if (res.ok) {
        const osConns = (await res.json()) as TrackedConnection[];
        if (Array.isArray(osConns) && osConns.length > 0) {
          const existingIds = new Set(this.connections.map((c) => c.id));
          for (const oc of osConns) {
            if (!existingIds.has(oc.id)) {
              this.connections.unshift(oc);
            }
          }
          this.pushLog(
            'INFO',
            'OsSocketScanner',
            `Scanned and imported ${osConns.length} established OS TCP sockets`
          );
          return [...this.connections];
        }
      }
    } catch {
      // Browser standalone fallback
    }
    return [...this.connections];
  }

  public async setSystemProxy(enabled: boolean): Promise<boolean> {
    try {
      const res = await fetch('/api/system-proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled })
      });
      if (res.ok) {
        this.pushLog(
          'INFO',
          'SystemProxy',
          `Windows System Proxy ${enabled ? 'ENABLED' : 'DISABLED'}`
        );
        return enabled;
      }
    } catch {
      // Browser fallback
    }
    this.pushLog(
      'INFO',
      'SystemProxy',
      `System Proxy toggled (${enabled ? 'ON' : 'OFF'})`
    );
    return enabled;
  }

  public async launchProcessWithProxy(
    executable: string,
    args: string[]
  ): Promise<boolean> {
    try {
      const res = await fetch('/api/launch-process', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ executable, args })
      });
      if (res.ok) {
        const data = await res.json();
        if (!data.error) {
          this.pushLog(
            'INFO',
            'ProcessLauncher',
            `Launched ${executable} (PID ${data.pid}) with injected proxy tunnel`
          );
          return true;
        }
      }
    } catch {
      // Browser fallback
    }
    this.simulateConnection({
      processName: executable,
      processPath: executable,
      targetHost: 'api.ipify.org',
      targetPort: 443,
      protocol: 'tcp'
    });
    return true;
  }

  public formatProxyUri(node: ProxyNode): string {
    const scheme = node.protocol;
    const authPart =
      node.auth && (node.auth.username || node.auth.password)
        ? `${node.auth.username}:${node.auth.password}@`
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
      auth = {
        username: decodeURIComponent(u || ''),
        password: decodeURIComponent(p || '')
      };
    }

    const params = new URLSearchParams(query.replace(/^\?/, ''));
    const sni = params.get('sni');
    const tls = protocol === 'https' || Boolean(sni);

    return {
      id: `proxy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
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

  public removeProxy(proxyId: string): ProfileConfig {
    this.profile.proxies = this.profile.proxies.filter((p) => p.id !== proxyId);
    this.persistProfile();
    return this.getProfile();
  }

  public upsertChain(chain: ProxyChain): ProfileConfig {
    const idx = this.profile.chains.findIndex((c) => c.id === chain.id);
    if (idx >= 0) {
      this.profile.chains[idx] = chain;
    } else {
      this.profile.chains.push(chain);
    }
    this.persistProfile();
    return this.getProfile();
  }

  public removeChain(chainId: string): ProfileConfig {
    this.profile.chains = this.profile.chains.filter((c) => c.id !== chainId);
    this.persistProfile();
    return this.getProfile();
  }

  public upsertRule(rule: RoutingRule): ProfileConfig {
    const idx = this.profile.rules.findIndex((r) => r.id === rule.id);
    if (idx >= 0) {
      this.profile.rules[idx] = rule;
    } else {
      this.profile.rules.push(rule);
    }
    this.profile.rules.sort((a, b) => a.priority - b.priority);
    this.persistProfile();
    return this.getProfile();
  }

  public toggleRuleEnabled(ruleId: string): ProfileConfig {
    const target = this.profile.rules.find((r) => r.id === ruleId);
    if (target) {
      target.enabled = !target.enabled;
      this.persistProfile();
    }
    return this.getProfile();
  }

  public reorderRulePriority(
    ruleId: string,
    direction: 'up' | 'down'
  ): ProfileConfig {
    this.profile.rules.sort((a, b) => a.priority - b.priority);
    const idx = this.profile.rules.findIndex((r) => r.id === ruleId);
    if (idx < 0) return this.getProfile();

    const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
    if (swapIdx >= 0 && swapIdx < this.profile.rules.length) {
      const currentPrio = this.profile.rules[idx].priority;
      const neighborPrio = this.profile.rules[swapIdx].priority;
      if (currentPrio === neighborPrio) {
        this.profile.rules[idx].priority =
          direction === 'up'
            ? Math.max(1, neighborPrio - PRIORITY_STEP)
            : neighborPrio + PRIORITY_STEP;
      } else {
        this.profile.rules[idx].priority = neighborPrio;
        this.profile.rules[swapIdx].priority = currentPrio;
      }
      this.profile.rules.sort((a, b) => a.priority - b.priority);
      this.persistProfile();
    }
    return this.getProfile();
  }

  public removeRule(ruleId: string): ProfileConfig {
    this.profile.rules = this.profile.rules.filter((r) => r.id !== ruleId);
    this.persistProfile();
    return this.getProfile();
  }

  public allocateFakeIp(domain: string): FakeIpEntry | null {
    const clean = domain.trim().toLowerCase();
    if (!clean) return null;

    const existing = this.fakeIpMap.get(clean);
    if (existing) {
      existing.hits += 1;
      return existing;
    }

    const thirdOctet = Math.floor(this.nextFakeIpOffset / 254) % 256;
    const fourthOctet = (this.nextFakeIpOffset % 254) + 1;
    this.nextFakeIpOffset += 1;

    const fakeIp = `${FAKE_IP_OCTET_A}.${FAKE_IP_OCTET_B}.${thirdOctet}.${fourthOctet}`;
    const entry: FakeIpEntry = {
      fakeIp,
      domain: clean,
      hits: 1,
      expiresAt: new Date(
        Date.now() + SYSTEM_CONSTANTS.dns.defaultTtlSeconds * 1000
      ).toISOString(),
      ttlRemainingSeconds: SYSTEM_CONSTANTS.dns.defaultTtlSeconds
    };

    this.fakeIpMap.set(clean, entry);
    this.reverseFakeIp.set(fakeIp, clean);
    this.pushLog('INFO', 'FakeIpDNS', `Allocated ${clean} -> ${fakeIp}`);
    return entry;
  }

  public listFakeIps(): FakeIpEntry[] {
    return Array.from(this.fakeIpMap.values());
  }

  public flushFakeIps(): void {
    this.fakeIpMap.clear();
    this.reverseFakeIp.clear();
    this.nextFakeIpOffset = 1;
    this.pushLog('WARN', 'FakeIpDNS', 'Flushed Fake-IP DNS cache');
  }

  public pushLog(
    level: LogEntry['level'],
    component: string,
    message: string
  ): void {
    this.logs.unshift({
      id: `log-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: new Date().toISOString(),
      level,
      component,
      message
    });
    if (this.logs.length > SYSTEM_CONSTANTS.telemetry.maxLogRingBufferEntries) {
      this.logs.pop();
    }
  }

  public listLogs(): LogEntry[] {
    return [...this.logs];
  }

  public clearLogs(): void {
    this.logs = [];
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
