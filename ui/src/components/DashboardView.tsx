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

import React from 'react';
import { useTranslation } from 'react-i18next';
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  Briefcase,
  Cpu,
  Gamepad2,
  Globe,
  Lock,
  Power,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Wand2
} from 'lucide-react';
import { formatBytes } from '../services/ipc';
import {
  ProxyNode,
  RoutingRule,
  SecurityPolicyConfig,
  SystemDiagnostics,
  TelemetrySnapshot
} from '../types/routeward';
import { HelpTooltip } from './HelpTooltip';
import { ExperienceMode } from './QuickSetupWizardModal';

export type DashboardUseCaseId = 'privacy' | 'work' | 'gaming' | 'strict';

interface DashboardViewProps {
  telemetry: TelemetrySnapshot;
  diagnostics: SystemDiagnostics;
  dnsCount: number;
  securityPolicy: SecurityPolicyConfig;
  experienceMode: ExperienceMode;
  proxies?: ProxyNode[];
  rules?: RoutingRule[];
  onToggleEngine?: () => void;
  onApplyUseCase?: (useCase: DashboardUseCaseId) => void;
  onTestPrimaryProxy?: (proxyId: string) => void;
  onNavigateProxy?: () => void;
  onUpdateSecurityPolicy: (partial: Partial<SecurityPolicyConfig>) => void;
  onOpenWizard: () => void;
  onNavigateRules: () => void;
  onSwitchToExpert: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  telemetry,
  diagnostics,
  dnsCount,
  securityPolicy,
  experienceMode,
  proxies = [],
  rules = [],
  onToggleEngine,
  onApplyUseCase,
  onTestPrimaryProxy,
  onNavigateProxy,
  onUpdateSecurityPolicy,
  onOpenWizard,
  onNavigateRules,
  onSwitchToExpert
}) => {
  const { t } = useTranslation();

  const isEngineRunning = diagnostics.daemonConnected && diagnostics.running;
  const primaryProxy = proxies.find((p) => p.enabled) ?? null;
  const protectedRuleCount = rules.filter(
    (r) =>
      r.enabled &&
      (r.action.type === 'proxy' ||
        r.action.type === 'chain' ||
        r.action.type === 'block')
  ).length;
  const totalTrafficBytes = telemetry.totalRxBytes + telemetry.totalTxBytes;

  const totalActions =
    telemetry.proxiedCount + telemetry.directCount + telemetry.blockedCount || 1;
  const proxiedPct = Math.round((telemetry.proxiedCount / totalActions) * 100);
  const directPct = Math.round((telemetry.directCount / totalActions) * 100);
  const blockedPct = Math.round((telemetry.blockedCount / totalActions) * 100);

  const maxSpeed = Math.max(
    1024,
    ...telemetry.bandwidthHistory.map((s) =>
      Math.max(s.rxBytesPerSec, s.txBytesPerSec)
    )
  );

  const maxProcessBytes = Math.max(
    1,
    ...(telemetry.topTalkers || []).map((p) => p.rxBytes + p.txBytes)
  );

  return (
    <div className="space-y-6">
      {/* Reassuring Health Summary Banner (Always visible, front and center for beginners) */}
      <div
        className={`tf-card flex flex-wrap items-center justify-between gap-4 border-l-4 p-5 ${
          isEngineRunning ? 'border-l-tf-green' : 'border-l-tf-red'
        }`}
      >
        <div className="flex items-start gap-3.5">
          <div
            className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-tf-lg ${
              isEngineRunning
                ? 'bg-tf-green/20 text-tf-green'
                : 'bg-tf-red/20 text-tf-red'
            }`}
          >
            {isEngineRunning ? (
              <ShieldCheck className="h-6 w-6" />
            ) : (
              <ShieldAlert className="h-6 w-6" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-tf-primary">
                {isEngineRunning
                  ? t('dashboard.health_banner.protected_title')
                  : t('dashboard.health_banner.paused_title')}
              </h2>
              <span
                className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${
                  isEngineRunning
                    ? 'bg-tf-green/20 text-tf-green'
                    : 'bg-tf-red/20 text-tf-red'
                }`}
              >
                {isEngineRunning
                  ? t('dashboard.health_banner.status_badge_ok')
                  : t('dashboard.health_banner.status_badge_off')}
              </span>
            </div>
            <p className="mt-1 max-w-2xl text-xs text-tf-secondary">
              {isEngineRunning
                ? t('dashboard.health_banner.protected_desc')
                : t('dashboard.health_banner.paused_desc')}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {experienceMode === 'simple' && onToggleEngine && (
            <button
              type="button"
              disabled={!diagnostics.daemonConnected}
              onClick={onToggleEngine}
              className={`flex items-center gap-2 rounded-tf-md px-4 py-2 text-xs font-bold transition disabled:cursor-not-allowed disabled:opacity-50 ${
                isEngineRunning
                  ? 'border border-tf-orange/40 bg-tf-orange/15 text-tf-orange hover:bg-tf-orange/25'
                  : 'bg-tf-green text-tf-bg hover:opacity-90'
              }`}
            >
              <Power className="h-3.5 w-3.5" />
              {isEngineRunning
                ? t('app.header.engine.pause')
                : t('app.header.engine.start')}
            </button>
          )}
          <button
            onClick={onOpenWizard}
            className="tf-btn-accent flex items-center gap-2 px-3.5 py-2 text-xs"
          >
            <Wand2 className="h-3.5 w-3.5" />
            {t('dashboard.health_banner.quick_wizard_cta')}
          </button>
          <button
            onClick={onNavigateRules}
            className="tf-surface-alt flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-tf-primary hover:border-tf-accent"
          >
            <Sparkles className="h-3.5 w-3.5 text-tf-accent" />
            {t('dashboard.health_banner.choose_apps_cta')}
          </button>
        </div>
      </div>

      {experienceMode === 'simple' ? (
        <>
          {/* Active Proxy Status Summary Card */}
          <div className="tf-card flex flex-wrap items-center justify-between gap-4 p-5">
            <div className="flex items-center gap-3.5">
              <div className="flex h-10 w-10 items-center justify-center rounded-tf-md bg-tf-cyan/15 text-tf-cyan">
                <Server className="h-5 w-5" />
              </div>
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-tf-secondary">
                  {t('dashboard.simple.proxy_summary_label')}
                </div>
                {primaryProxy ? (
                  <div className="mt-0.5 flex flex-wrap items-center gap-2">
                    <span className="text-sm font-bold text-tf-primary">
                      {primaryProxy.name}
                    </span>
                    <span className="rounded-tf-sm bg-tf-surface-alt px-2 py-0.5 font-mono text-[11px] text-tf-cyan">
                      {primaryProxy.protocol.toUpperCase()} - {primaryProxy.host}:
                      {primaryProxy.port}
                    </span>
                    {primaryProxy.lastLatencyMs !== null && (
                      <span className="rounded-tf-sm bg-tf-green/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-tf-green">
                        {primaryProxy.lastLatencyMs} ms
                      </span>
                    )}
                    {primaryProxy.exitIp && (
                      <span className="font-mono text-xs text-tf-secondary">
                        ({primaryProxy.exitIp})
                      </span>
                    )}
                  </div>
                  ) : (
                    <div className="mt-0.5 flex flex-wrap items-center gap-2">
                      <span className="rounded-tf-sm bg-tf-green/15 px-2 py-0.5 text-xs font-bold text-tf-green">
                        {t('dashboard.simple.direct_filter_mode_title')}
                      </span>
                      <span className="text-xs text-tf-secondary">
                        {t('dashboard.simple.direct_filter_mode_desc')}
                      </span>
                    </div>
                  )}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {primaryProxy && onTestPrimaryProxy && (
                <button
                  type="button"
                  onClick={() => onTestPrimaryProxy(primaryProxy.id)}
                  className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-cyan hover:border-tf-cyan"
                >
                  <Activity className="h-3.5 w-3.5" />
                  {t('dashboard.simple.test_proxy_cta')}
                </button>
              )}
              {onNavigateProxy && (
                <button
                  type="button"
                  onClick={onNavigateProxy}
                  className="tf-btn-primary flex items-center gap-1.5 px-3 py-1.5 text-xs"
                >
                  <Server className="h-3.5 w-3.5" />
                  {primaryProxy
                    ? t('dashboard.simple.configure_proxy_cta')
                    : t('dashboard.simple.add_optional_proxy_cta')}
                </button>
              )}
            </div>
          </div>

          {/* 3 Reassuring Human Metrics */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="tf-card p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-tf-secondary">
                  {t('dashboard.simple.metric_protected_apps')}
                </span>
                <Shield className="h-4 w-4 text-tf-accent" />
              </div>
              <div className="mt-2 text-2xl font-bold text-tf-primary">
                {protectedRuleCount}
              </div>
            </div>

            <div className="tf-card p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-tf-secondary">
                  {t('dashboard.simple.metric_leaks_blocked')}
                </span>
                <ShieldAlert className="h-4 w-4 text-tf-green" />
              </div>
              <div className="mt-2 text-2xl font-bold text-tf-green">
                {telemetry.blockedCount}
              </div>
            </div>

            <div className="tf-card p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-tf-secondary">
                  {t('dashboard.simple.metric_protected_traffic')}
                </span>
                <Globe className="h-4 w-4 text-tf-cyan" />
              </div>
              <div className="mt-2 text-2xl font-bold text-tf-cyan">
                {formatBytes(totalTrafficBytes)}
              </div>
            </div>
          </div>

          {/* 4 Use-Case Scenario Preset Cards */}
          <div className="tf-card p-5">
            <h3 className="text-sm font-bold text-tf-primary">
              {t('dashboard.simple.use_cases_title')}
            </h3>
            <p className="mt-0.5 text-xs text-tf-secondary">
              {t('dashboard.simple.use_cases_subtitle')}
            </p>
            <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {(
                [
                  {
                    id: 'privacy' as DashboardUseCaseId,
                    icon: ShieldCheck,
                    color: 'text-tf-green',
                    title: t('dashboard.simple.uc_privacy_title'),
                    desc: t('dashboard.simple.uc_privacy_desc')
                  },
                  {
                    id: 'work' as DashboardUseCaseId,
                    icon: Briefcase,
                    color: 'text-tf-cyan',
                    title: t('dashboard.simple.uc_work_title'),
                    desc: t('dashboard.simple.uc_work_desc')
                  },
                  {
                    id: 'gaming' as DashboardUseCaseId,
                    icon: Gamepad2,
                    color: 'text-tf-orange',
                    title: t('dashboard.simple.uc_gaming_title'),
                    desc: t('dashboard.simple.uc_gaming_desc')
                  },
                  {
                    id: 'strict' as DashboardUseCaseId,
                    icon: Lock,
                    color: 'text-tf-purple',
                    title: t('dashboard.simple.uc_strict_title'),
                    desc: t('dashboard.simple.uc_strict_desc')
                  }
                ]
              ).map((card) => {
                const CardIcon = card.icon;
                return (
                  <button
                    key={card.id}
                    type="button"
                    onClick={() => onApplyUseCase?.(card.id)}
                    className="tf-surface-alt flex flex-col items-start gap-2 rounded-tf-md p-4 text-left transition hover:border-tf-accent"
                  >
                    <CardIcon className={`h-5 w-5 ${card.color}`} />
                    <div className="text-xs font-bold text-tf-primary">
                      {card.title}
                    </div>
                    <p className="text-[11px] leading-relaxed text-tf-secondary">
                      {card.desc}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="flex justify-center">
            <button
              type="button"
              onClick={onSwitchToExpert}
              className="tf-surface-alt flex items-center gap-2 px-4 py-2 text-xs font-medium text-tf-secondary hover:border-tf-cyan hover:text-tf-cyan"
            >
              <Terminal className="h-3.5 w-3.5" />
              {t('dashboard.health_banner.switch_expert_cta')}
            </button>
          </div>
        </>
      ) : (
        <>
          {/* KPI Cards with Educational Tooltips */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="tf-card p-4">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-tf-secondary">
              {t('dashboard.kpi.active_connections.label')}
              <HelpTooltip text={t('dashboard.tooltips.active_connections')} />
            </span>
            <Activity className="h-4 w-4 text-tf-accent" />
          </div>
          <div className="mt-2 text-2xl font-bold text-tf-primary">
            {telemetry.activeConnections}
          </div>
          <div className="mt-1 text-xs text-tf-secondary">
            {t('dashboard.kpi.active_connections.subtext')}
          </div>
        </div>

        <div className="tf-card p-4">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-tf-secondary">
              {t('dashboard.kpi.download_speed.label')}
              <HelpTooltip text={t('dashboard.tooltips.download_speed')} />
            </span>
            <ArrowDownLeft className="h-4 w-4 text-tf-cyan" />
          </div>
          <div className="mt-2 text-2xl font-bold text-tf-cyan">
            {formatBytes(telemetry.downloadBytesPerSec)}/s
          </div>
          <div className="mt-1 text-xs text-tf-secondary">
            {t('dashboard.kpi.download_speed.subtext')} (
            {formatBytes(telemetry.totalRxBytes)})
          </div>
        </div>

        <div className="tf-card p-4">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-tf-secondary">
              {t('dashboard.kpi.upload_speed.label')}
              <HelpTooltip text={t('dashboard.tooltips.upload_speed')} />
            </span>
            <ArrowUpRight className="h-4 w-4 text-tf-pink" />
          </div>
          <div className="mt-2 text-2xl font-bold text-tf-pink">
            {formatBytes(telemetry.uploadBytesPerSec)}/s
          </div>
          <div className="mt-1 text-xs text-tf-secondary">
            {t('dashboard.kpi.upload_speed.subtext')} (
            {formatBytes(telemetry.totalTxBytes)})
          </div>
        </div>

        <div className="tf-card p-4">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-tf-secondary">
              {t('dashboard.kpi.dns_mappings.label')}
              <HelpTooltip text={t('dashboard.tooltips.dns_mappings')} />
            </span>
            <Globe className="h-4 w-4 text-tf-green" />
          </div>
          <div className="mt-2 text-2xl font-bold text-tf-green">{dnsCount}</div>
          <div className="mt-1 text-xs text-tf-secondary">
            {t('dashboard.kpi.dns_mappings.subtext')} ({diagnostics.fakeIpCidr})
          </div>
        </div>
      </div>

      {/* Bandwidth Graph & Action Distribution */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="tf-card flex flex-col justify-between p-5 lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-sm font-bold text-tf-primary">
              {t('dashboard.chart.bandwidth.title')}
            </h3>
            <div className="flex items-center gap-4 text-xs">
              <span className="flex items-center gap-1.5 text-tf-cyan">
                <span className="h-2.5 w-2.5 rounded-full bg-tf-cyan" />
                {t('dashboard.chart.bandwidth.download')}
              </span>
              <span className="flex items-center gap-1.5 text-tf-pink">
                <span className="h-2.5 w-2.5 rounded-full bg-tf-pink" />
                {t('dashboard.chart.bandwidth.upload')}
              </span>
            </div>
          </div>

          <div className="flex h-44 items-end gap-1.5 rounded-tf-md border border-tf-border bg-tf-bg p-3">
            {telemetry.bandwidthHistory.length === 0 ? (
              <div className="flex h-full w-full items-center justify-center text-xs text-tf-secondary">
                {t('dashboard.chart.bandwidth.empty')}
              </div>
            ) : (
              telemetry.bandwidthHistory.slice(-30).map((sample, idx) => {
                const rxHeight = Math.max(
                  6,
                  Math.round((sample.rxBytesPerSec / maxSpeed) * 100)
                );
                const txHeight = Math.max(
                  4,
                  Math.round((sample.txBytesPerSec / maxSpeed) * 100)
                );
                return (
                  <div
                    key={idx}
                    className="flex h-full flex-1 flex-col justify-end gap-0.5"
                    title={`${sample.timestamp} - RX: ${formatBytes(
                      sample.rxBytesPerSec
                    )}/s | TX: ${formatBytes(sample.txBytesPerSec)}/s`}
                  >
                    <div
                      className="w-full rounded-t-tf-xs bg-tf-cyan/80 transition-all"
                      style={{ height: `${rxHeight}%` }}
                    />
                    <div
                      className="w-full rounded-b-tf-xs bg-tf-pink/80 transition-all"
                      style={{ height: `${txHeight}%` }}
                    />
                  </div>
                );
              })
            )}
          </div>
        </div>

        <div className="tf-card flex flex-col justify-between p-5">
          <h3 className="mb-4 text-sm font-bold text-tf-primary">
            {t('dashboard.chart.distribution.title')}
          </h3>

          <div className="space-y-4">
            <div>
              <div className="mb-1 flex justify-between text-xs">
                <span className="font-medium text-tf-accent">
                  {t('dashboard.chart.distribution.proxied')}
                </span>
                <span className="text-tf-secondary">
                  {telemetry.proxiedCount} ({proxiedPct}%)
                </span>
              </div>
              <div className="h-2.5 w-full overflow-hidden rounded-full bg-tf-surface-alt">
                <div
                  className="h-full bg-tf-accent"
                  style={{ width: `${proxiedPct}%` }}
                />
              </div>
            </div>

            <div>
              <div className="mb-1 flex justify-between text-xs">
                <span className="font-medium text-tf-green">
                  {t('dashboard.chart.distribution.direct')}
                </span>
                <span className="text-tf-secondary">
                  {telemetry.directCount} ({directPct}%)
                </span>
              </div>
              <div className="h-2.5 w-full overflow-hidden rounded-full bg-tf-surface-alt">
                <div
                  className="h-full bg-tf-green"
                  style={{ width: `${directPct}%` }}
                />
              </div>
            </div>

            <div>
              <div className="mb-1 flex justify-between text-xs">
                <span className="font-medium text-tf-red">
                  {t('dashboard.chart.distribution.blocked')}
                </span>
                <span className="text-tf-secondary">
                  {telemetry.blockedCount} ({blockedPct}%)
                </span>
              </div>
              <div className="h-2.5 w-full overflow-hidden rounded-full bg-tf-surface-alt">
                <div
                  className="h-full bg-tf-red"
                  style={{ width: `${blockedPct}%` }}
                />
              </div>
            </div>
          </div>

          <div className="tf-surface-alt mt-4 p-3 text-xs text-tf-secondary">
            <div className="flex items-center gap-2 font-semibold text-tf-primary">
              {!diagnostics.daemonConnected ? (
                <ShieldAlert className="h-4 w-4 text-tf-orange" />
              ) : (
                <ShieldCheck className="h-4 w-4 text-tf-green" />
              )}
              <span>
                {!diagnostics.daemonConnected
                  ? t('dashboard.system.status.admin_unknown')
                  : diagnostics.elevatedPrivileges
                    ? t('dashboard.system.status.admin_elevated')
                    : t('dashboard.system.status.admin_standard')}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Top-Talkers by Process & Privacy Shield Controls */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Top-Talkers */}
        <div className="tf-card p-5">
          <div className="mb-4">
            <h3 className="text-sm font-bold text-tf-primary">
              {t('dashboard.top_talkers.panel.title')}
            </h3>
            <p className="text-xs text-tf-secondary">
              {t('dashboard.top_talkers.panel.subtitle')}
            </p>
          </div>

          <div className="space-y-3">
            {!telemetry.topTalkers || telemetry.topTalkers.length === 0 ? (
              <div className="py-6 text-center text-xs text-tf-secondary">
                {t('dashboard.top_talkers.panel.empty')}
              </div>
            ) : (
              telemetry.topTalkers.slice(0, 5).map((talker) => {
                const total = talker.rxBytes + talker.txBytes;
                const widthPct = Math.max(
                  6,
                  Math.round((total / maxProcessBytes) * 100)
                );
                return (
                  <div
                    key={talker.processName}
                    className="tf-surface-alt space-y-1.5 p-3"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2 font-semibold text-tf-primary">
                        <Terminal className="h-3.5 w-3.5 text-tf-accent" />
                        <span>{talker.processName}</span>
                        <span className="rounded bg-tf-bg px-1.5 py-0.5 font-mono text-[10px] text-tf-secondary">
                          {talker.activeSockets}{' '}
                          {t('dashboard.top_talkers.panel.sockets')}
                        </span>
                      </div>
                      <div className="font-mono text-[11px]">
                        <span className="text-tf-cyan">
                          ↓ {formatBytes(talker.rxBytes)}
                        </span>{' '}
                        /{' '}
                        <span className="text-tf-pink">
                          ↑ {formatBytes(talker.txBytes)}
                        </span>
                      </div>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-tf-bg">
                      <div
                        className="h-full bg-tf-accent transition-all"
                        style={{ width: `${widthPct}%` }}
                      />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Privacy Shield & Anti-Leak Controls */}
        <div className="tf-card p-5">
          <div className="mb-4">
            <h3 className="text-sm font-bold text-tf-primary">
              {t('dashboard.security_shield.panel.title')}
            </h3>
            <p className="text-xs text-tf-secondary">
              {t('dashboard.security_shield.panel.subtitle')}
            </p>
          </div>

          <div className="space-y-3">
            <div className="tf-surface-alt flex items-center justify-between p-3">
              <div className="flex items-start gap-3">
                <ShieldAlert className="mt-0.5 h-4 w-4 text-tf-accent" />
                <div>
                  <div className="flex items-center gap-1.5 text-xs font-bold text-tf-primary">
                    {t('dashboard.security_shield.panel.killswitch_title')}
                    <HelpTooltip text={t('dashboard.tooltips.killswitch')} />
                  </div>
                  <div className="text-[11px] text-tf-secondary">
                    {t('dashboard.security_shield.panel.killswitch_desc')}
                  </div>
                </div>
              </div>
              <input
                type="checkbox"
                aria-label={t('dashboard.security_shield.panel.killswitch_aria')}
                checked={securityPolicy.killSwitchEnabled}
                onChange={(e) =>
                  onUpdateSecurityPolicy({
                    killSwitchEnabled: e.target.checked
                  })
                }
                className="h-4 w-4 cursor-pointer accent-tf-accent"
              />
            </div>

            <div className="tf-surface-alt flex items-center justify-between p-3">
              <div className="flex items-start gap-3">
                <Lock className="mt-0.5 h-4 w-4 text-tf-cyan" />
                <div>
                  <div className="flex items-center gap-1.5 text-xs font-bold text-tf-primary">
                    {t('dashboard.security_shield.panel.udp_guard_title')}
                    <HelpTooltip text={t('dashboard.tooltips.udp_guard')} />
                  </div>
                  <div className="text-[11px] text-tf-secondary">
                    {t('dashboard.security_shield.panel.udp_guard_desc')}
                  </div>
                </div>
              </div>
              <input
                type="checkbox"
                aria-label={t('dashboard.security_shield.panel.udp_guard_aria')}
                checked={securityPolicy.blockUdpOnTcpOnlyProxy}
                onChange={(e) =>
                  onUpdateSecurityPolicy({
                    blockUdpOnTcpOnlyProxy: e.target.checked
                  })
                }
                className="h-4 w-4 cursor-pointer accent-tf-accent"
              />
            </div>

            <div className="tf-surface-alt flex items-center justify-between p-3">
              <div className="flex items-start gap-3">
                <Globe className="mt-0.5 h-4 w-4 text-tf-green" />
                <div>
                  <div className="flex items-center gap-1.5 text-xs font-bold text-tf-primary">
                    {t('dashboard.security_shield.panel.dns_guard_title')}
                    <HelpTooltip text={t('dashboard.tooltips.dns_guard')} />
                  </div>
                  <div className="text-[11px] text-tf-secondary">
                    {t('dashboard.security_shield.panel.dns_guard_desc')}
                  </div>
                </div>
              </div>
              <input
                type="checkbox"
                aria-label={t('dashboard.security_shield.panel.dns_guard_aria')}
                checked={securityPolicy.strictDnsNoLocalFallback}
                onChange={(e) =>
                  onUpdateSecurityPolicy({
                    strictDnsNoLocalFallback: e.target.checked
                  })
                }
                className="h-4 w-4 cursor-pointer accent-tf-accent"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Subsystem Diagnostics (Expert Mode) */}
      <div className="tf-card p-5">
        <div className="mb-3 flex items-center gap-2">
          <Cpu className="h-4 w-4 text-tf-accent" />
          <h3 className="text-sm font-bold text-tf-primary">
            {t('dashboard.system.status.title')}
          </h3>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="tf-surface-alt p-3">
            <div className="text-[11px] uppercase text-tf-secondary">
              {t('dashboard.system.status.os_label')}
            </div>
            <div className="mt-1 font-mono text-sm font-bold text-tf-primary">
              {diagnostics.osName}
            </div>
          </div>
          <div className="tf-surface-alt p-3">
            <div className="text-[11px] uppercase text-tf-secondary">
              {t('dashboard.system.status.relay_tcp_label')}
            </div>
            <div className="mt-1 flex items-center gap-1.5 font-mono text-sm font-bold text-tf-cyan">
              <Server className="h-3.5 w-3.5" />
              {diagnostics.relayTcpEndpoint}
            </div>
          </div>
          <div className="tf-surface-alt p-3">
            <div className="text-[11px] uppercase text-tf-secondary">
              {t('dashboard.system.status.relay_http_label')}
            </div>
            <div className="mt-1 font-mono text-sm font-bold text-tf-orange">
              {diagnostics.relayHttpEndpoint}
            </div>
          </div>
          <div className="tf-surface-alt p-3">
            <div className="text-[11px] uppercase text-tf-secondary">
              {t('dashboard.system.status.dns_server_label')}
            </div>
            <div className="mt-1 font-mono text-sm font-bold text-tf-green">
              {diagnostics.dnsEndpoint}
            </div>
          </div>
        </div>
      </div>
        </>
      )}
    </div>
  );
};
