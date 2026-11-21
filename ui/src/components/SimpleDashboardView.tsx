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

import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Activity,
  Briefcase,
  CheckCircle2,
  Circle,
  ClipboardPaste,
  Clock,
  Gamepad2,
  Globe,
  LifeBuoy,
  Lock,
  Power,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  X
} from 'lucide-react';
import { formatBytes } from '../services/format';
import {
  ProxyHealthReport,
  ProxyNode,
  RoutingRule,
  SecurityPolicyConfig,
  SystemDiagnostics,
  TelemetrySnapshot
} from '../types/routeward';
import { DashboardUseCaseId } from './DashboardView';

interface SimpleDashboardViewProps {
  telemetry: TelemetrySnapshot;
  diagnostics: SystemDiagnostics;
  securityPolicy: SecurityPolicyConfig;
  proxies: ProxyNode[];
  rules: RoutingRule[];
  startingProtection: boolean;
  pauseRemainingSec: number | null;
  onToggleEngine?: () => void;
  onTemporaryPause?: (minutes: number) => Promise<void> | void;
  onStartAndEnableProtection?: () => Promise<void> | void;
  onApplyUseCase?: (
    useCase: DashboardUseCaseId
  ) => Promise<boolean | void> | boolean | void;
  onTestPrimaryProxy?: (
    proxyId: string
  ) => Promise<ProxyHealthReport | null | void> | void;
  onCheckDirectIp?: () => Promise<string | null>;
  onPasteFromClipboard?: () => Promise<void> | void;
  onNavigateProxy?: () => void;
  onUpdateSecurityPolicy: (partial: Partial<SecurityPolicyConfig>) => void;
  onOpenWizard: () => void;
  onOpenTroubleshoot?: () => void;
  onNavigateRules: () => void;
  onSwitchToExpert: () => void;
}

export const SimpleDashboardView: React.FC<SimpleDashboardViewProps> = ({
  telemetry,
  diagnostics,
  securityPolicy,
  proxies,
  rules,
  startingProtection,
  pauseRemainingSec,
  onToggleEngine,
  onTemporaryPause,
  onStartAndEnableProtection,
  onApplyUseCase,
  onTestPrimaryProxy,
  onCheckDirectIp,
  onPasteFromClipboard,
  onNavigateProxy,
  onUpdateSecurityPolicy,
  onOpenWizard,
  onOpenTroubleshoot,
  onNavigateRules,
  onSwitchToExpert
}) => {
  const { t } = useTranslation();
  const [testingPrimaryProxy, setTestingPrimaryProxy] = useState(false);
  const [lastProxyTestStatus, setLastProxyTestStatus] = useState<
    'ok' | 'failed' | null
  >(null);
  const [showProtectionCheck, setShowProtectionCheck] = useState(false);
  const [verifyingProtection, setVerifyingProtection] = useState(false);
  const [verifiedExitIp, setVerifiedExitIp] = useState<string | null>(null);
  const [verifiedDirectIp, setVerifiedDirectIp] = useState<string | null>(null);
  const [applyingUseCase, setApplyingUseCase] =
    useState<DashboardUseCaseId | null>(null);
  const [lastAppliedUseCase, setLastAppliedUseCase] =
    useState<DashboardUseCaseId | null>(null);

  const isEngineRunning = diagnostics.daemonConnected && diagnostics.running;
  const primaryProxy = proxies.find((p) => p.enabled) ?? null;

  useEffect(() => {
    setLastProxyTestStatus(null);
  }, [primaryProxy?.id]);

  const handleTestPrimaryProxyClick = async (proxyId: string) => {
    if (!onTestPrimaryProxy || testingPrimaryProxy) return;
    setTestingPrimaryProxy(true);
    try {
      const report = await Promise.resolve(onTestPrimaryProxy(proxyId));
      if (report && typeof report === 'object' && 'reachable' in report) {
        setLastProxyTestStatus(report.reachable ? 'ok' : 'failed');
        if (report.exitIp) {
          setVerifiedExitIp(report.exitIp);
        }
      } else if (report === null) {
        setLastProxyTestStatus('failed');
      }
    } catch {
      setLastProxyTestStatus('failed');
    } finally {
      setTestingPrimaryProxy(false);
    }
  };

  const handleVerifyProtection = async () => {
    setShowProtectionCheck(true);
    setVerifyingProtection(true);
    try {
      const tasks: Array<Promise<unknown>> = [];
      if (primaryProxy && onTestPrimaryProxy) {
        tasks.push(handleTestPrimaryProxyClick(primaryProxy.id));
      }
      if (onCheckDirectIp) {
        tasks.push(
          onCheckDirectIp()
            .then((ip) => setVerifiedDirectIp(ip))
            .catch(() => {})
        );
      }
      await Promise.all(tasks);
    } finally {
      setVerifyingProtection(false);
    }
  };

  const handleApplyUseCaseClick = async (id: DashboardUseCaseId) => {
    if (!onApplyUseCase || applyingUseCase) return;
    let maybePromise: Promise<boolean | void> | boolean | void;
    try {
      maybePromise = onApplyUseCase(id);
    } catch {
      return;
    }
    if (
      maybePromise &&
      typeof (maybePromise as Promise<boolean | void>).then === 'function'
    ) {
      setApplyingUseCase(id);
      try {
        const result = await maybePromise;
        if (result !== false) {
          setLastAppliedUseCase(id);
        }
      } catch {
        // Error toast is handled by caller; do not mark scenario as applied.
      } finally {
        setApplyingUseCase(null);
      }
    } else if (maybePromise !== false) {
      setLastAppliedUseCase(id);
    }
  };

  const stepServiceReady = diagnostics.daemonConnected;
  const stepProtectionReady = isEngineRunning;
  const stepConfigReady = rules.length > 0 || Boolean(primaryProxy);
  const showReadinessChecklist = !(
    stepServiceReady &&
    stepProtectionReady &&
    stepConfigReady
  );
  const protectedRuleCount = rules.filter(
    (r) =>
      r.enabled &&
      (r.action.type === 'proxy' ||
        r.action.type === 'chain' ||
        r.action.type === 'block')
  ).length;
  const totalTrafficBytes = telemetry.totalRxBytes + telemetry.totalTxBytes;

  return (
    <div className="space-y-6">
      {/* Focused Hero Protection Banner (1 primary CTA + optional temporary pause) */}
      <div
        className={`tf-card space-y-4 border-l-4 p-5 ${
          isEngineRunning ? 'border-l-tf-green' : 'border-l-tf-red'
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
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
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-sm font-bold text-tf-primary">
                  {isEngineRunning
                    ? t('dashboard.health_banner.protected_title')
                    : !diagnostics.daemonConnected
                      ? t('app.daemon_banner.simple_disconnected_title')
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
                {!isEngineRunning &&
                  pauseRemainingSec !== null &&
                  pauseRemainingSec > 0 && (
                    <span className="inline-flex items-center gap-1 rounded-full bg-tf-orange/20 px-2 py-0.5 font-mono text-[10px] font-bold text-tf-orange">
                      <Clock className="h-3 w-3" />
                      {t('dashboard.simple.auto_resume_in', {
                        remaining: `${Math.floor(pauseRemainingSec / 60)}:${String(
                          pauseRemainingSec % 60
                        ).padStart(2, '0')}`
                      })}
                    </span>
                  )}
              </div>
              <p className="mt-1 max-w-2xl text-xs text-tf-secondary">
                {isEngineRunning
                  ? t('dashboard.health_banner.protected_desc')
                  : !diagnostics.daemonConnected
                    ? diagnostics.osName === 'WINDOWS'
                      ? t('app.daemon_banner.simple_disconnected_desc')
                      : t('app.daemon_banner.simple_disconnected_non_windows')
                    : t('dashboard.health_banner.paused_desc')}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {!diagnostics.daemonConnected &&
              diagnostics.osName === 'WINDOWS' &&
              onStartAndEnableProtection && (
                <button
                  type="button"
                  disabled={startingProtection}
                  onClick={() => {
                    void onStartAndEnableProtection();
                  }}
                  className="flex items-center gap-2 rounded-tf-md bg-tf-green px-4 py-2 text-xs font-bold text-tf-bg transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Power className="h-3.5 w-3.5" />
                  {startingProtection
                    ? t('app.header.engine.starting_protection')
                    : t('app.header.engine.start_protection')}
                </button>
              )}
            {diagnostics.daemonConnected && onToggleEngine && (
              <>
                <button
                  type="button"
                  onClick={onToggleEngine}
                  className={`flex items-center gap-2 rounded-tf-md px-4 py-2 text-xs font-bold transition ${
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
                {isEngineRunning && onTemporaryPause && (
                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      onClick={() => {
                        void onTemporaryPause(15);
                      }}
                      className="tf-surface-alt flex items-center gap-1 px-2.5 py-2 text-[11px] font-semibold text-tf-secondary hover:border-tf-orange hover:text-tf-orange"
                    >
                      <Clock className="h-3 w-3" />
                      {t('dashboard.simple.pause_15m')}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        void onTemporaryPause(60);
                      }}
                      className="tf-surface-alt flex items-center gap-1 px-2.5 py-2 text-[11px] font-semibold text-tf-secondary hover:border-tf-orange hover:text-tf-orange"
                    >
                      <Clock className="h-3 w-3" />
                      {t('dashboard.simple.pause_60m')}
                    </button>
                  </div>
                )}
              </>
            )}
          </div>
        </div>

        {/* Dedicated 2-button Self-Check & Troubleshoot Bar */}
        <div className="flex flex-wrap items-center gap-2 border-t border-tf-border pt-3">
          <button
            type="button"
            disabled={verifyingProtection}
            onClick={() => {
              void handleVerifyProtection();
            }}
            className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-cyan hover:border-tf-cyan disabled:opacity-60"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            {verifyingProtection
              ? t('dashboard.simple.testing_proxy')
              : t('dashboard.simple.verify_protection_cta')}
          </button>
          {onOpenTroubleshoot && (
            <button
              type="button"
              onClick={onOpenTroubleshoot}
              className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-orange hover:border-tf-orange"
            >
              <LifeBuoy className="h-3.5 w-3.5" />
              {t('dashboard.simple.troubleshoot_cta')}
            </button>
          )}
        </div>
      </div>

      {/* Protection Self-Check Panel (with close button, loading state & paused awareness) */}
      {showProtectionCheck && (
        <div className="tf-card space-y-3 border-l-4 border-l-tf-cyan p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-tf-cyan">
              {t('dashboard.simple.verify_panel_title')}
            </h3>
            <div className="flex items-center gap-2">
              {(!securityPolicy.killSwitchEnabled ||
                !securityPolicy.strictDnsNoLocalFallback) && (
                <button
                  type="button"
                  onClick={() =>
                    onUpdateSecurityPolicy({
                      killSwitchEnabled: true,
                      strictDnsNoLocalFallback: true,
                      blockUdpOnTcpOnlyProxy: true,
                      blockQuicUdp443: true,
                      blockEncryptedDnsBypass: true
                    })
                  }
                  className="tf-btn-accent px-3 py-1 text-[11px] font-bold"
                >
                  {t('dashboard.simple.verify_fix_all')}
                </button>
              )}
              <button
                type="button"
                onClick={() => setShowProtectionCheck(false)}
                aria-label={t('dashboard.simple.verify_close')}
                className="rounded-tf-sm p-1.5 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {!isEngineRunning && (
            <p className="rounded-tf-md border border-tf-orange/40 bg-tf-orange/10 px-3 py-2 text-xs font-semibold text-tf-orange">
              {t('dashboard.simple.verify_paused_notice')}
            </p>
          )}

          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
            <div className="tf-surface-alt p-3 text-xs">
              <div className="text-[11px] text-tf-secondary">
                {t('dashboard.simple.verify_ip_label')}
              </div>
              {(() => {
                const effectiveExitIp = verifiedExitIp || primaryProxy?.exitIp || null;
                const sameAsDirect =
                  Boolean(verifiedDirectIp && effectiveExitIp) &&
                  verifiedDirectIp === effectiveExitIp;
                return (
                  <>
                    <div
                      className={`mt-1 font-bold ${
                        verifyingProtection
                          ? 'text-tf-cyan'
                          : lastProxyTestStatus === 'failed'
                            ? 'text-tf-red'
                            : sameAsDirect
                              ? 'text-tf-orange'
                              : isEngineRunning
                                ? 'text-tf-green'
                                : 'text-tf-orange'
                      }`}
                    >
                      {verifyingProtection
                        ? t('dashboard.simple.verify_checking')
                        : !primaryProxy
                          ? t('dashboard.simple.verify_ip_direct')
                          : lastProxyTestStatus === 'failed'
                            ? t('dashboard.simple.verify_ip_unreachable')
                            : sameAsDirect && effectiveExitIp
                              ? t('dashboard.simple.verify_ip_same_warning', {
                                  exitIp: effectiveExitIp
                                })
                              : `${t('dashboard.simple.verify_ip_masked')}${
                                  effectiveExitIp ? ` (${effectiveExitIp})` : ''
                                }`}
                    </div>
                    {!verifyingProtection &&
                      verifiedDirectIp &&
                      effectiveExitIp &&
                      !sameAsDirect && (
                        <div className="mt-1 font-mono text-[10px] text-tf-secondary">
                          {t('dashboard.simple.verify_before_after', {
                            directIp: verifiedDirectIp,
                            exitIp: effectiveExitIp
                          })}
                        </div>
                      )}
                  </>
                );
              })()}
            </div>
            <div className="tf-surface-alt p-3 text-xs">
              <div className="text-[11px] text-tf-secondary">
                {t('dashboard.simple.verify_dns_label')}
              </div>
              <div
                className={`mt-1 font-bold ${
                  isEngineRunning && securityPolicy.strictDnsNoLocalFallback
                    ? 'text-tf-green'
                    : 'text-tf-orange'
                }`}
              >
                {isEngineRunning && securityPolicy.strictDnsNoLocalFallback
                  ? t('dashboard.simple.verify_status_ok')
                  : t('dashboard.simple.verify_status_off')}
              </div>
            </div>
            <div className="tf-surface-alt p-3 text-xs">
              <div className="text-[11px] text-tf-secondary">
                {t('dashboard.simple.verify_killswitch_label')}
              </div>
              <div
                className={`mt-1 font-bold ${
                  isEngineRunning && securityPolicy.killSwitchEnabled
                    ? 'text-tf-green'
                    : 'text-tf-orange'
                }`}
              >
                {isEngineRunning && securityPolicy.killSwitchEnabled
                  ? t('dashboard.simple.verify_status_ok')
                  : t('dashboard.simple.verify_status_off')}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Clickable Beginner 3-Step Readiness Checklist */}
      {showReadinessChecklist && (
        <div className="tf-card p-4">
          <div className="text-xs font-bold uppercase tracking-wider text-tf-accent">
            {t('dashboard.simple.checklist_title')}
          </div>
          <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-3">
            {[
              {
                done: stepServiceReady,
                label: t('dashboard.simple.checklist_step_service'),
                onClick:
                  !stepServiceReady &&
                  diagnostics.osName === 'WINDOWS' &&
                  onStartAndEnableProtection
                    ? () => {
                        void onStartAndEnableProtection();
                      }
                    : undefined
              },
              {
                done: stepProtectionReady,
                label: t('dashboard.simple.checklist_step_protection'),
                onClick: !stepProtectionReady
                  ? diagnostics.daemonConnected && onToggleEngine
                    ? onToggleEngine
                    : diagnostics.osName === 'WINDOWS' &&
                        onStartAndEnableProtection
                      ? () => {
                          void onStartAndEnableProtection();
                        }
                      : undefined
                  : undefined
              },
              {
                done: stepConfigReady,
                label: t('dashboard.simple.checklist_step_rules'),
                onClick: !stepConfigReady ? onNavigateRules : undefined
              }
            ].map((item, idx) =>
              item.onClick ? (
                <button
                  key={idx}
                  type="button"
                  onClick={item.onClick}
                  className="flex items-center gap-2 rounded-tf-md border border-tf-border bg-tf-surface-alt px-3 py-2 text-left text-xs font-semibold text-tf-primary transition hover:border-tf-accent hover:text-tf-accent"
                >
                  <Circle className="h-4 w-4 shrink-0 text-tf-accent" />
                  <span>
                    {idx + 1}. {item.label}
                  </span>
                </button>
              ) : (
                <div
                  key={idx}
                  className={`flex items-center gap-2 rounded-tf-md border px-3 py-2 text-xs font-semibold ${
                    item.done
                      ? 'border-tf-green/40 bg-tf-green/10 text-tf-green'
                      : 'border-tf-border bg-tf-surface-alt text-tf-secondary'
                  }`}
                >
                  {item.done ? (
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-tf-green" />
                  ) : (
                    <Circle className="h-4 w-4 shrink-0 text-tf-secondary" />
                  )}
                  <span>
                    {idx + 1}. {item.label}
                  </span>
                </div>
              )
            )}
          </div>
        </div>
      )}

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
                {lastProxyTestStatus === 'failed' ? (
                  <span className="rounded-tf-sm bg-tf-red/15 px-2 py-0.5 text-[11px] font-bold text-tf-red">
                    {t('dashboard.simple.proxy_status_failed')}
                  </span>
                ) : primaryProxy.lastLatencyMs !== null ? (
                  <span className="rounded-tf-sm bg-tf-green/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-tf-green">
                    {t('dashboard.simple.proxy_status_ok')} (
                    {primaryProxy.lastLatencyMs} ms)
                  </span>
                ) : (
                  <span className="rounded-tf-sm bg-tf-surface-alt px-2 py-0.5 text-[11px] text-tf-secondary">
                    {t('dashboard.simple.proxy_status_untested')}
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
              disabled={testingPrimaryProxy}
              onClick={() => {
                void handleTestPrimaryProxyClick(primaryProxy.id);
              }}
              className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-cyan hover:border-tf-cyan disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Activity className="h-3.5 w-3.5" />
              {testingPrimaryProxy
                ? t('dashboard.simple.testing_proxy')
                : t('dashboard.simple.test_proxy_cta')}
            </button>
          )}
          {!primaryProxy && onPasteFromClipboard && (
            <button
              type="button"
              onClick={() => {
                void onPasteFromClipboard();
              }}
              className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-green hover:border-tf-green"
            >
              <ClipboardPaste className="h-3.5 w-3.5" />
              {t('dashboard.simple.paste_clipboard_cta')}
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
            const isApplied = lastAppliedUseCase === card.id;
            const isApplying = applyingUseCase === card.id;
            return (
              <button
                key={card.id}
                type="button"
                disabled={applyingUseCase !== null}
                onClick={() => {
                  void handleApplyUseCaseClick(card.id);
                }}
                className={`tf-surface-alt flex flex-col items-start gap-2 rounded-tf-md p-4 text-left transition hover:border-tf-accent disabled:opacity-60 ${
                  isApplied ? 'border-tf-green bg-tf-green/10' : ''
                }`}
              >
                <div className="flex w-full items-center justify-between gap-2">
                  <CardIcon className={`h-5 w-5 ${card.color}`} />
                  {isApplied && !isApplying && (
                    <span className="rounded-full bg-tf-green/20 px-2 py-0.5 text-[10px] font-bold text-tf-green">
                      {t('dashboard.simple.use_case_applied_badge')}
                    </span>
                  )}
                </div>
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

      <div className="flex flex-wrap items-center justify-center gap-3">
        <button
          type="button"
          onClick={onOpenWizard}
          className="tf-surface-alt flex items-center gap-2 px-4 py-2 text-xs font-medium text-tf-accent hover:border-tf-accent"
        >
          {t('dashboard.health_banner.quick_wizard_cta')}
        </button>
        <button
          type="button"
          onClick={onSwitchToExpert}
          className="tf-surface-alt flex items-center gap-2 px-4 py-2 text-xs font-medium text-tf-secondary hover:border-tf-cyan hover:text-tf-cyan"
        >
          <Terminal className="h-3.5 w-3.5" />
          {t('dashboard.health_banner.switch_expert_cta')}
        </button>
      </div>
    </div>
  );
};
