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

export type InterceptionMode = 'hybrid' | 'driver' | 'relay';
export type ProxyProtocol = 'socks5' | 'socks4' | 'http' | 'https';
export type TransportProtocol = 'tcp' | 'udp' | 'any';
export type ConnectionStatus = 'active' | 'closed' | 'blocked';
export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';
export type ChainStrategy =
  | 'sequence'
  | 'failover'
  | 'lowest_latency'
  | 'load_balance';

export type ThemeFamily = 'Root' | 'Dark' | 'Light' | 'Alt';
export type AccentTint =
  | 'Default'
  | 'Blue'
  | 'Cyan'
  | 'Green'
  | 'Orange'
  | 'Pink'
  | 'Purple'
  | 'Red'
  | 'Yellow';

export interface ThemeForgeColors {
  Background: string;
  CurrentLine: string;
  Selection: string;
  Foreground: string;
  Comment: string;
  Cyan: string;
  Green: string;
  Orange: string;
  Pink: string;
  Purple: string;
  Red: string;
  Yellow: string;
  Surface: string;
  SurfaceAlt: string;
  Accent: string;
  AccentHover: string;
  AccentPressed: string;
  TextPrimary: string;
  TextSecondary: string;
  Border: string;
  Success: string;
  Warning: string;
  Error: string;
  Info: string;
  Blue: string;
}

export interface ThemeForgePalette {
  version: number;
  name: string;
  displayName: string;
  family: ThemeFamily;
  isLight?: boolean;
  isHighContrast?: boolean;
  attribution: string;
  colors: ThemeForgeColors;
}

export interface ProxyCredentials {
  username: string;
  password?: string;
  hasPassword?: boolean;
}

export interface ProxyNode {
  id: string;
  name: string;
  protocol: ProxyProtocol;
  host: string;
  port: number;
  auth: ProxyCredentials | null;
  udpEnabled: boolean;
  tls: boolean;
  tlsSkipVerify?: boolean;
  sni: string | null;
  enabled: boolean;
  lastLatencyMs: number | null;
  exitIp: string | null;
}

export interface ProxyChain {
  id: string;
  name: string;
  strategy?: ChainStrategy;
  proxyIds: string[];
  enabled: boolean;
}

export interface PortRange {
  start: number;
  end: number;
}

export interface RuleAction {
  type: 'direct' | 'block' | 'proxy' | 'chain';
  targetId?: string;
}

export interface RoutingRule {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  processPatterns: string[];
  domainPatterns: string[];
  ipCidrs: string[];
  portRanges: PortRange[];
  protocol: TransportProtocol;
  action: RuleAction;
  /** When set, the rule stops applying at that instant and the daemon removes it (temporary unblock). */
  expiresAt?: string | null;
}

export interface DnsConfig {
  enableFakeIp: boolean;
  remoteDnsResolution: boolean;
  fakeIpCidr: string;
  upstreamDns: string;
  bypassDomains: string[];
  dnsServerProcesses?: string[];
}

export interface SecurityPolicyConfig {
  killSwitchEnabled: boolean;
  blockUdpOnTcpOnlyProxy: boolean;
  blockQuicUdp443?: boolean;
  strictDnsNoLocalFallback: boolean;
  blockEncryptedDnsBypass?: boolean;
  unknownProcessAction?: RuleAction;
}

export interface ProfileConfig {
  profileId: string;
  name: string;
  version: string;
  enableLogging?: boolean;
  interceptionMode: InterceptionMode;
  themeConfig: {
    theme: string;
    accent: AccentTint;
  };
  securityPolicy?: SecurityPolicyConfig;
  defaultAction: RuleAction;
  dnsConfig: DnsConfig;
  proxies: ProxyNode[];
  chains: ProxyChain[];
  rules: RoutingRule[];
}

export interface TrackedConnection {
  id: string;
  pid: number;
  processName: string;
  processPath: string;
  targetHost: string;
  resolvedDomain: string | null;
  targetPort: number;
  protocol: TransportProtocol;
  matchedRule: string;
  routeLabel: string;
  latencyMs: number;
  rxBytes: number;
  txBytes: number;
  status: ConnectionStatus;
  startedAt: string;
  errorDetail?: string | null;
  /** Why the connection was blocked; absent on records from older daemons. */
  blockReason?: BlockReason;
  /** Identifier of the rule that decided; absent when no rule applied. */
  matchedRuleId?: string;
  /** Proxy that failed, for kill switch blocks. */
  proxyId?: string;
  targetIp?: string;
  /** True for records created by a socket scan or a simulation, never by real traffic. */
  simulated?: boolean;
}

export interface ProfileSummary {
  profileId: string;
  name: string;
  proxyCount: number;
  ruleCount: number;
  active: boolean;
}

export interface SystemApplicationEntry {
  name: string;
  executablePath: string;
  running: boolean;
}

export interface DetectedProxyCandidate {
  name: string;
  protocol: ProxyProtocol;
  host: string;
  port: number;
  source: string;
}

export interface CurrentNetworkInfo {
  networkName: string | null;
  kind: string;
}

export interface PacStatus {
  enabled: boolean;
  pacUrl: string;
}

export interface AutostartStatus {
  enabled: boolean;
}

export interface FoxyProxyImportResult {
  proxies: ProxyNode[];
  rules: RoutingRule[];
  skippedEntries: number;
}

export interface BandwidthSample {
  timestamp: string;
  rxBytesPerSec: number;
  txBytesPerSec: number;
}

export interface ProcessTrafficSummary {
  processName: string;
  activeSockets: number;
  totalConnections: number;
  rxBytes: number;
  txBytes: number;
}

export interface TelemetrySnapshot {
  activeConnections: number;
  downloadBytesPerSec: number;
  uploadBytesPerSec: number;
  totalRxBytes: number;
  totalTxBytes: number;
  proxiedCount: number;
  directCount: number;
  blockedCount: number;
  bandwidthHistory: BandwidthSample[];
  topTalkers: ProcessTrafficSummary[];
}

export interface SystemDiagnostics {
  daemonConnected: boolean;
  running: boolean;
  osName: string;
  interceptionMode: InterceptionMode;
  elevatedPrivileges: boolean;
  relayTcpEndpoint: string;
  relayHttpEndpoint: string;
  dnsEndpoint: string;
  fakeIpCidr: string;
  activeLocale: string;
  /** Unix time in milliseconds at which a running pause ends, null when protection is not paused. */
  pausedUntilEpochMs: number | null;
  /** Error key of the last failed automatic start of protection, null when there is none. */
  autoStartErrorKey: string | null;
}

export interface FakeIpEntry {
  fakeIp: string;
  domain: string;
  hits: number;
  expiresAt: string;
  ttlRemainingSeconds: number;
}

export interface LogContext {
  pid?: number;
  connectionId?: string;
  host?: string;
  port?: number;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  component: string;
  message: string;
  context?: LogContext;
}

/** Why a connection was blocked (mirrors the engine's BlockReason, camelCase). */
export type BlockReason =
  | 'ruleBlock'
  | 'defaultPolicyBlock'
  | 'killSwitchProxyUnreachable'
  | 'killSwitchProxyRefused'
  | 'killSwitchProxyTimeout'
  | 'killSwitchProxyAuthRejected'
  | 'killSwitchProxyHandshake'
  | 'killSwitchProxyMisconfigured'
  | 'udpProxyUnsupported'
  | 'killSwitchDirectUdpFailed'
  | 'fragmentedUdpBlocked'
  | 'unknownProcessPolicy'
  | 'unknownProcessKillSwitch'
  | 'fakeIpEgressGuard'
  | 'quicBlocked'
  | 'encryptedDnsBlocked'
  | 'localNameGuard'
  | 'dnsServerBlockedByRule'
  | 'unknown';

/** One aggregated line of the daemon's blocked summary. */
export interface BlockedSummaryEntry {
  processName: string;
  processPath: string;
  /** Domain when known, else the IP address. */
  destination: string;
  targetPort: number;
  protocol: TransportProtocol;
  blockReason: BlockReason;
  matchedRuleId?: string;
  matchedRule?: string;
  proxyId?: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
  lastConnectionId: string;
  lastPid: number;
  lastErrorDetail?: string;
}

/** Packets dropped without an owning application (never listed as rows). */
export interface BlockedCounters {
  droppedUnattributedSyn: number;
  droppedUnattributedUdp: number;
  [extra: string]: number | undefined;
}

export interface BlockedResponse {
  entries: BlockedSummaryEntry[];
  counters: BlockedCounters;
}

/** Where a log query reads from: the live memory ring or one daemon file by date (yyyyMMdd). */
export type LogQuerySource = 'memory' | { daemonFile: { date: string } };

export interface QueryLogsRequest {
  source: LogQuerySource;
  minLevel?: LogLevel;
  components?: string[];
  text?: string;
  pid?: number;
  connectionId?: string;
  /** Epoch milliseconds. */
  since?: number;
  until?: number;
  limit: number;
  cursor?: string;
}

export interface QueryLogsResponse {
  entries: LogEntry[];
  truncated: boolean;
  /** Dates (yyyyMMdd) of the log files the daemon holds. */
  availableDates: string[];
  nextCursor?: string;
}

export type FindingSeverity = 'info' | 'warning' | 'critical';

export interface FindingSubject {
  app?: string;
  site?: string;
  proxyId?: string;
  ruleId?: string;
}

export type FixAction =
  | { type: 'openProxy'; id: string }
  | { type: 'testProxy'; id: string }
  | { type: 'unblock'; key: Partial<BlockedSummaryEntry> }
  | { type: 'editRule'; id: string }
  | { type: 'pauseProtection' }
  | { type: 'openSetting'; key: string }
  | { type: 'restartApp' }
  | { type: 'runElevated' }
  | { type: 'none' };

export interface Finding {
  code: string;
  severity: FindingSeverity;
  subject: FindingSubject;
  evidenceCount: number;
  lastSeen?: string;
  fix: FixAction;
}

export interface AnalyzeResponse {
  findings: Finding[];
}

export interface CollectDiagnosticsRequest {
  logDays: number;
  includeConnections: boolean;
  includeProfile: boolean;
  maskDomains: boolean;
}

export interface DiagnosticSectionInfo {
  name: string;
  bytes: number;
}

export interface DiagnosticManifest {
  version: string | number;
  os?: string;
  generatedAt?: string;
  sections: DiagnosticSectionInfo[];
  /** Plain list of the redactions applied (for example "passwords", "proxy usernames"). */
  redactions?: string[];
  maskDomains?: boolean;
}

/** The redacted diagnostic file: a manifest describing the sections that follow. */
export interface DiagnosticBundle {
  manifest: DiagnosticManifest;
  [section: string]: unknown;
}

export interface PreviewRuleChangeRequest {
  upserts: RoutingRule[];
  removeIds: string[];
  request: ConnectionRequest;
}

export interface PreviewRuleChangeResponse {
  evaluation: RuleEvaluationResult;
  /** Set when a security policy would still block the connection despite the rule change. */
  policyOverride?: BlockReason;
}

export interface ConnectionRequest {
  processName: string;
  processPath?: string;
  targetHost: string;
  targetIp?: string;
  targetPort: number;
  protocol: TransportProtocol;
}

export interface RuleEvaluationResult {
  matchedRuleId: string;
  matchedRuleName: string;
  action: RuleAction;
  effectiveDomain: string | null;
  resolvedFromFakeIp: boolean;
}

export interface ProxyHealthReport {
  proxyId: string;
  reachable: boolean;
  latencyMs: number | null;
  udpSupported: boolean;
  exitIp: string | null;
  errorDetail: string | null;
}

export interface ToastNotification {
  id: string;
  message: string;
  severity: 'success' | 'info' | 'warning' | 'error';
  actionLabel?: string;
  onAction?: () => void;
}

export interface DaemonFullState {
  diagnostics: SystemDiagnostics;
  profile: ProfileConfig;
  telemetry: TelemetrySnapshot;
  connections: TrackedConnection[];
  logs: LogEntry[];
  fakeIps: FakeIpEntry[];
}

export type TelemetryEventPayload =
  | { event: 'telemetry'; data: TelemetrySnapshot }
  | { event: 'connectionUpdated'; data: TrackedConnection }
  | { event: 'connectionsCleared' }
  | { event: 'log'; data: LogEntry }
  | { event: 'logsCleared' };

export type IpcStreamEvent =
  | { streamType: 'event'; payload: TelemetryEventPayload }
  | { streamType: 'resync'; payload: { skippedEvents: number } };

declare global {
  interface Window {
    __ROUTEWARD_TOKEN__?: string;
  }
}
