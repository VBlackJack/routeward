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
}

export interface DnsConfig {
  enableFakeIp: boolean;
  remoteDnsResolution: boolean;
  fakeIpCidr: string;
  upstreamDns: string;
  bypassDomains: string[];
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
}

export interface FakeIpEntry {
  fakeIp: string;
  domain: string;
  hits: number;
  expiresAt: string;
  ttlRemainingSeconds: number;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  component: string;
  message: string;
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
