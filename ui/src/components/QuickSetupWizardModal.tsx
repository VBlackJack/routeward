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

import React, { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Activity,
  Briefcase,
  CheckCircle2,
  Gamepad2,
  Radar,
  Shield,
  Sparkles,
  Terminal,
  Wand2,
  X
} from 'lucide-react';
import { ModalContainer } from './ModalContainer';
import { SYSTEM_CONSTANTS, UI_CONFIG } from '../config/constants';
import { generateClientId } from '../services/ipc';
import { resolveSimpleProxyAction } from '../services/friendly';
import {
  DetectedProxyCandidate,
  ProxyChain,
  ProxyHealthReport,
  ProxyNode,
  ProxyProtocol,
  RoutingRule,
  TransportProtocol
} from '../types/routeward';

export type ExperienceMode = 'simple' | 'expert';
type GoalProfile = 'privacy' | 'work' | 'gaming';
type WizardProxyInputMode = 'link' | 'manual';

const WIZARD_PROTOCOLS: ProxyProtocol[] = ['socks5', 'http', 'https', 'socks4'];

interface QuickSetupWizardModalProps {
  proxies: ProxyNode[];
  chains: ProxyChain[];
  currentMode: ExperienceMode;
  onImportUris: (
    uriText: string
  ) => Promise<ProxyNode[] | number | void> | void;
  onAddProxy?: (proxy: ProxyNode) => Promise<ProxyNode[] | void> | void;
  onTestProxy?: (
    proxyId: string
  ) => Promise<ProxyHealthReport | null | void> | void;
  onDetectExistingProxies?: () => Promise<DetectedProxyCandidate[]>;
  onEnableProtection?: () => Promise<unknown> | void;
  onAddRule: (rule: RoutingRule) => Promise<unknown> | void;
  onSelectMode: (mode: ExperienceMode) => void;
  onComplete: (hasEnabledProxy?: boolean) => void;
  /** Called when applying the wizard fails; the modal stays open so the user can retry. */
  onError?: (err: unknown) => void;
  onClose: () => void;
}

const TOTAL_WIZARD_STEPS = 3;

export const QuickSetupWizardModal: React.FC<QuickSetupWizardModalProps> = ({
  proxies,
  chains,
  currentMode,
  onImportUris,
  onAddProxy,
  onTestProxy,
  onDetectExistingProxies,
  onEnableProtection,
  onAddRule,
  onSelectMode,
  onComplete,
  onError,
  onClose
}) => {
  const { t } = useTranslation();
  const titleId = useId();
  const uriTextareaId = useId();
  const manualFormId = useId();
  const [step, setStep] = useState(1);
  const [goal, setGoal] = useState<GoalProfile>('privacy');
  const [proxyInputMode, setProxyInputMode] =
    useState<WizardProxyInputMode>('link');
  const [customUri, setCustomUri] = useState('');
  const [manualName, setManualName] = useState('');
  const [manualProtocol, setManualProtocol] = useState<ProxyProtocol>('socks5');
  const [manualHost, setManualHost] = useState('');
  const [manualPort, setManualPort] = useState<string>(
    String(UI_CONFIG.DEFAULT_PROXY_PORT)
  );
  const [manualUsername, setManualUsername] = useState('');
  const [manualPassword, setManualPassword] = useState('');
  const [manualPortError, setManualPortError] = useState<string | null>(null);
  const [testingExisting, setTestingExisting] = useState(false);
  const [existingTestFeedback, setExistingTestFeedback] = useState<
    { ok: true; ms: number } | { ok: false } | null
  >(null);
  const [detectingProxies, setDetectingProxies] = useState(false);
  const [detectedCandidates, setDetectedCandidates] = useState<
    DetectedProxyCandidate[] | null
  >(null);
  const [persistedProxyList, setPersistedProxyList] = useState<ProxyNode[] | null>(
    null
  );
  const [enableProtectionNow, setEnableProtectionNow] = useState(true);
  const [selectedMode, setSelectedMode] = useState<ExperienceMode>(currentMode);
  const [applying, setApplying] = useState(false);

  const effectiveExistingProxies = persistedProxyList ?? proxies;
  const enabledExistingProxies = effectiveExistingProxies.filter((p) => p.enabled);

  const hasPlannedProxy =
    enabledExistingProxies.length > 0 ||
    (proxyInputMode === 'link' && Boolean(customUri.trim())) ||
    (proxyInputMode === 'manual' && Boolean(manualHost.trim()));

  const persistCurrentProxyInput = async (): Promise<ProxyNode[] | null> => {
    if (proxyInputMode === 'link' && customUri.trim()) {
      const importResult = await onImportUris(customUri.trim());
      if (Array.isArray(importResult)) {
        setPersistedProxyList(importResult);
        setCustomUri('');
        return importResult;
      }
      return effectiveExistingProxies;
    }
    if (proxyInputMode === 'manual' && manualHost.trim()) {
      const parsedPort = Number(manualPort.trim());
      if (
        !Number.isInteger(parsedPort) ||
        parsedPort < 1 ||
        parsedPort > UI_CONFIG.MAX_PORT
      ) {
        setManualPortError(t('proxies.modal.add_proxy.port_error'));
        setStep(2);
        return null;
      }
      const cleanHost = manualHost.trim();
      const cleanUser = manualUsername.trim();
      const effectiveTls = manualProtocol === 'https';
      const newNode: ProxyNode = {
        id: generateClientId('proxy'),
        name:
          manualName.trim() ||
          `${manualProtocol.toUpperCase()} ${cleanHost}:${parsedPort}`,
        protocol: manualProtocol,
        host: cleanHost,
        port: parsedPort,
        auth:
          cleanUser || manualPassword
            ? {
                username: cleanUser,
                ...(manualPassword ? { password: manualPassword } : {}),
                hasPassword: Boolean(manualPassword)
              }
            : null,
        udpEnabled: manualProtocol === 'socks5',
        tls: effectiveTls,
        tlsSkipVerify: false,
        sni: effectiveTls ? cleanHost : null,
        enabled: true,
        lastLatencyMs: null,
        exitIp: null
      };
      if (onAddProxy) {
        const addResult = await onAddProxy(newNode);
        const nextList = Array.isArray(addResult)
          ? addResult
          : [...effectiveExistingProxies, newNode];
        setPersistedProxyList(nextList);
        setManualHost('');
        return nextList;
      }
      const authPrefix = cleanUser
        ? `${encodeURIComponent(cleanUser)}${manualPassword ? `:${encodeURIComponent(manualPassword)}` : ''}@`
        : '';
      const fallbackUri = `${manualProtocol}://${authPrefix}${cleanHost}:${parsedPort}#${encodeURIComponent(newNode.name)}`;
      const importResult = await onImportUris(fallbackUri);
      if (Array.isArray(importResult)) {
        setPersistedProxyList(importResult);
        setManualHost('');
        return importResult;
      }
      return effectiveExistingProxies;
    }
    return effectiveExistingProxies;
  };

  const handleTestProxyInWizard = async () => {
    if (!onTestProxy || testingExisting) return;
    setTestingExisting(true);
    setExistingTestFeedback(null);
    try {
      let currentList = effectiveExistingProxies;
      const hasDraftInput =
        (proxyInputMode === 'link' && Boolean(customUri.trim())) ||
        (proxyInputMode === 'manual' && Boolean(manualHost.trim()));
      if (hasDraftInput) {
        const persisted = await persistCurrentProxyInput();
        if (!persisted) {
          return;
        }
        currentList = persisted;
      }
      const enabledList = currentList.filter((p) => p.enabled);
      const target = hasDraftInput
        ? enabledList[enabledList.length - 1]
        : enabledList[0];
      if (!target) {
        setExistingTestFeedback({ ok: false });
        return;
      }
      const report = await Promise.resolve(onTestProxy(target.id));
      if (report && typeof report === 'object' && 'reachable' in report) {
        if (report.reachable) {
          setExistingTestFeedback({ ok: true, ms: report.latencyMs ?? 0 });
        } else {
          setExistingTestFeedback({ ok: false });
        }
      } else {
        setExistingTestFeedback({ ok: false });
      }
    } catch {
      setExistingTestFeedback({ ok: false });
    } finally {
      setTestingExisting(false);
    }
  };

  const handleDetectInWizard = async () => {
    if (!onDetectExistingProxies || detectingProxies) return;
    setDetectingProxies(true);
    try {
      const found = await onDetectExistingProxies();
      setDetectedCandidates(found);
    } finally {
      setDetectingProxies(false);
    }
  };

  const handlePickDetectedCandidate = (cand: DetectedProxyCandidate) => {
    setProxyInputMode('manual');
    setManualName(cand.name);
    setManualProtocol(cand.protocol);
    setManualHost(cand.host);
    setManualPort(String(cand.port));
    setManualPortError(null);
    setDetectedCandidates(null);
  };

  const applySelectedGoalRules = async () => {
    if (applying) return;
    setApplying(true);
    try {
      const postImportProxies = await persistCurrentProxyInput();
      if (!postImportProxies) {
        return;
      }

      const enabledProxies = postImportProxies.filter((p) => p.enabled);
      const simpleProxyAction = resolveSimpleProxyAction(
        postImportProxies,
        chains
      );
      const primaryProxyId = enabledProxies[0]?.id;
      const hasEnabledProxy = Boolean(primaryProxyId);
      const enabledChains = hasEnabledProxy
        ? chains.filter(
            (c) =>
              c.enabled &&
              c.proxyIds.some((pid) => enabledProxies.some((p) => p.id === pid))
          )
        : [];

      const findPreset = (id: string) =>
        SYSTEM_CONSTANTS.rulePresets.find((p) => p.id === id);

      if (goal === 'gaming') {
        const gamingApp = SYSTEM_CONSTANTS.visualAppCatalog.find(
          (c) => c.id === 'app-gaming'
        );
        if (gamingApp) {
          await onAddRule({
            id: `rule-visual-${gamingApp.id}`,
            name: t(`${gamingApp.i18nKey}.name`),
            enabled: true,
            priority: gamingApp.priority,
            processPatterns: [...gamingApp.processPatterns],
            domainPatterns: [],
            ipCidrs: [],
            portRanges: [],
            protocol: 'any',
            action: { type: 'direct' }
          });
        }
      }

      const presetsToApply: string[] =
        goal === 'privacy'
          ? [
              ...(hasEnabledProxy ? ['preset-privacy-browsers'] : []),
              'preset-block-os-telemetry',
              'preset-rfc1918-direct'
            ]
          : goal === 'work'
            ? [
                ...(hasEnabledProxy ? ['preset-dev-toolchains'] : []),
                'preset-rfc1918-direct'
              ]
            : [
                ...(hasEnabledProxy ? ['preset-privacy-browsers'] : []),
                'preset-rfc1918-direct'
              ];

      for (const pid of presetsToApply) {
        const preset = findPreset(pid);
        if (!preset) continue;
        let actType = preset.suggestedActionType as
          | 'proxy'
          | 'chain'
          | 'direct'
          | 'block';
        let targetId: string | undefined;
        if (actType === 'proxy') {
          if (simpleProxyAction) {
            actType = simpleProxyAction.type;
            targetId = simpleProxyAction.targetId;
          } else {
            targetId = primaryProxyId;
          }
        } else if (actType === 'chain') {
          if (enabledChains[0]?.id) {
            targetId = enabledChains[0].id;
          } else if (primaryProxyId) {
            actType = 'proxy';
            targetId = primaryProxyId;
          }
        }
        if ((actType === 'proxy' || actType === 'chain') && !targetId) {
          continue;
        }

        await onAddRule({
          id: `rule-wiz-${preset.id}`,
          name: t(`${preset.i18nKey}.name`),
          enabled: true,
          priority: preset.priority,
          processPatterns: [...preset.processPatterns],
          domainPatterns: [...preset.domainPatterns],
          ipCidrs: [...preset.ipCidrs],
          portRanges: preset.portRanges.map((r) => ({
            start: r.start,
            end: r.end
          })),
          protocol: preset.protocol as TransportProtocol,
          action: targetId ? { type: actType, targetId } : { type: actType }
        });
      }

      onSelectMode(selectedMode);
      if (enableProtectionNow && onEnableProtection) {
        await onEnableProtection();
      }
      onComplete(hasEnabledProxy);
      onClose();
    } catch (err) {
      onError?.(err);
    } finally {
      setApplying(false);
    }
  };

  return (
    <ModalContainer
      onClose={onClose}
      labelledBy={titleId}
      backdropClassName="bg-black/75 p-4 backdrop-blur-sm"
    >
      <div className="tf-card w-full max-w-xl p-6 shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-tf-border pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-tf-lg bg-tf-accent/20 text-tf-accent">
              <Wand2 className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 id={titleId} className="text-base font-bold text-tf-primary">
                  {t('wizard.modal.title')}
                </h2>
                <span className="rounded bg-tf-surface-alt px-2 py-0.5 font-mono text-[10px] font-bold text-tf-accent">
                  {t('wizard.modal.step_indicator')} {step}/{TOTAL_WIZARD_STEPS}
                </span>
              </div>
              <p className="text-xs text-tf-secondary">
                {t('wizard.modal.subtitle')}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={t('app.titlebar.close')}
            className="rounded-tf-sm p-1 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Step 1: Goal */}
        {step === 1 && (
          <div className="mt-5 space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-tf-accent">
              {t('wizard.modal.step1_title')}
            </h3>
            {(
              [
                {
                  id: 'privacy',
                  icon: Shield,
                  title: t('wizard.modal.step1_privacy_title'),
                  desc: t('wizard.modal.step1_privacy_desc')
                },
                {
                  id: 'work',
                  icon: Briefcase,
                  title: t('wizard.modal.step1_work_title'),
                  desc: t('wizard.modal.step1_work_desc')
                },
                {
                  id: 'gaming',
                  icon: Gamepad2,
                  title: t('wizard.modal.step1_gaming_title'),
                  desc: t('wizard.modal.step1_gaming_desc')
                }
              ] as const
            ).map((item) => {
              const Icon = item.icon;
              const active = goal === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setGoal(item.id)}
                  className={`flex w-full items-start gap-3.5 rounded-tf-md border p-3.5 text-left transition ${
                    active
                      ? 'border-tf-accent bg-tf-accent/10'
                      : 'border-tf-border bg-tf-surface-alt hover:border-tf-accent/50'
                  }`}
                >
                  <Icon className="mt-0.5 h-5 w-5 shrink-0 text-tf-accent" />
                  <div className="flex-1">
                    <div className="text-xs font-bold text-tf-primary">
                      {item.title}
                    </div>
                    <div className="mt-0.5 text-[11px] text-tf-secondary">
                      {item.desc}
                    </div>
                  </div>
                  {active && (
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-tf-accent" />
                  )}
                </button>
              );
            })}
          </div>
        )}

        {/* Step 2: Proxy Connection */}
        {step === 2 && (
          <div className="mt-5 space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-tf-accent">
              {t('wizard.modal.step2_title')}
            </h3>

            {enabledExistingProxies[0] ? (
              <div className="tf-surface-alt space-y-2 p-3.5 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <div className="font-bold text-tf-primary">
                      {t('wizard.modal.step2_use_existing')}
                    </div>
                    <div className="mt-0.5 font-mono text-[11px] text-tf-cyan">
                      {`${enabledExistingProxies[0].name} (${enabledExistingProxies[0].protocol.toUpperCase()} - ${enabledExistingProxies[0].host}:${enabledExistingProxies[0].port})`}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {onTestProxy && (
                      <button
                        type="button"
                        disabled={testingExisting}
                        onClick={() => {
                          void handleTestProxyInWizard();
                        }}
                        className="tf-surface flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-semibold text-tf-cyan hover:border-tf-cyan disabled:opacity-60"
                      >
                        <Activity className="h-3.5 w-3.5" />
                        {testingExisting
                          ? t('dashboard.simple.testing_proxy')
                          : t('wizard.modal.step2_test_button')}
                      </button>
                    )}
                    <CheckCircle2 className="h-5 w-5 shrink-0 text-tf-green" />
                  </div>
                </div>
                {existingTestFeedback && (
                  <p
                    className={`text-[11px] font-semibold ${
                      existingTestFeedback.ok ? 'text-tf-green' : 'text-tf-red'
                    }`}
                  >
                    {existingTestFeedback.ok
                      ? t('wizard.modal.step2_test_ok', {
                          ms: existingTestFeedback.ms
                        })
                      : t('wizard.modal.step2_test_failed')}
                  </p>
                )}
              </div>
            ) : (
              <div className="rounded-tf-md border border-tf-cyan/30 bg-tf-cyan/10 p-3.5 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-bold text-tf-primary">
                    {t('wizard.modal.step2_no_proxy_title')}
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setCustomUri('');
                      setManualHost('');
                      setStep(3);
                    }}
                    className="rounded-tf-md bg-tf-green/20 px-2.5 py-1 text-[11px] font-bold text-tf-green hover:bg-tf-green/30"
                  >
                    {t('wizard.modal.step2_skip_direct_cta')}
                  </button>
                </div>
                <p className="mt-1 text-[11px] text-tf-secondary">
                  {t('wizard.modal.step2_no_proxy_desc')}
                </p>
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                aria-pressed={proxyInputMode === 'link'}
                onClick={() => setProxyInputMode('link')}
                className={`flex-1 rounded-tf-md px-3 py-1.5 text-xs font-bold transition ${
                  proxyInputMode === 'link'
                    ? 'bg-tf-accent text-tf-bg'
                    : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
                }`}
              >
                {t('wizard.modal.step2_tab_link')}
              </button>
              <button
                type="button"
                aria-pressed={proxyInputMode === 'manual'}
                onClick={() => setProxyInputMode('manual')}
                className={`flex-1 rounded-tf-md px-3 py-1.5 text-xs font-bold transition ${
                  proxyInputMode === 'manual'
                    ? 'bg-tf-accent text-tf-bg'
                    : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
                }`}
              >
                {t('wizard.modal.step2_tab_manual')}
              </button>
              {onDetectExistingProxies && (
                <button
                  type="button"
                  disabled={detectingProxies}
                  onClick={() => {
                    void handleDetectInWizard();
                  }}
                  className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-cyan hover:border-tf-cyan disabled:opacity-60"
                >
                  <Radar className="h-3.5 w-3.5" />
                  {detectingProxies
                    ? t('proxies.simple.detecting')
                    : t('wizard.modal.step2_detect_button')}
                </button>
              )}
            </div>

            {detectedCandidates !== null && (
              <div className="tf-surface-alt space-y-2 p-3 text-xs">
                {detectedCandidates.length === 0 ? (
                  <p className="text-[11px] text-tf-secondary">
                    {t('proxies.simple.detect_empty')}
                  </p>
                ) : (
                  detectedCandidates.map((cand) => (
                    <div
                      key={`${cand.protocol}-${cand.host}-${cand.port}`}
                      className="flex items-center justify-between gap-2 rounded bg-tf-surface px-2.5 py-1.5"
                    >
                      <span className="font-mono text-[11px] text-tf-cyan">
                        {cand.name} ({cand.protocol.toUpperCase()} {cand.host}:
                        {cand.port})
                      </span>
                      <button
                        type="button"
                        onClick={() => handlePickDetectedCandidate(cand)}
                        className="tf-btn-accent px-2.5 py-1 text-[11px]"
                      >
                        {t('proxies.simple.detect_import')}
                      </button>
                    </div>
                  ))
                )}
              </div>
            )}

            {proxyInputMode === 'link' ? (
              <div>
                <label
                  htmlFor={uriTextareaId}
                  className="mb-1.5 block text-xs font-medium text-tf-secondary"
                >
                  {t('wizard.modal.step2_paste_uri')}
                </label>
                <textarea
                  id={uriTextareaId}
                  rows={3}
                  value={customUri}
                  onChange={(e) => setCustomUri(e.target.value)}
                  placeholder={t('wizard.modal.step2_uri_placeholder')}
                  className="tf-input w-full p-2.5 font-mono text-xs"
                />
              </div>
            ) : (
              <div className="space-y-2.5">
                <div className="grid grid-cols-3 gap-2.5">
                  <div>
                    <label
                      htmlFor={`${manualFormId}-protocol`}
                      className="block text-[11px] text-tf-secondary"
                    >
                      {t('wizard.modal.step2_manual_protocol')}
                    </label>
                    <select
                      id={`${manualFormId}-protocol`}
                      value={manualProtocol}
                      onChange={(e) =>
                        setManualProtocol(e.target.value as ProxyProtocol)
                      }
                      className="tf-input mt-1 w-full px-2 py-1.5 text-xs uppercase"
                    >
                      {WIZARD_PROTOCOLS.map((p) => (
                        <option key={p} value={p}>
                          {p.toUpperCase()}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label
                      htmlFor={`${manualFormId}-host`}
                      className="block text-[11px] text-tf-secondary"
                    >
                      {t('wizard.modal.step2_manual_host')}
                    </label>
                    <input
                      id={`${manualFormId}-host`}
                      type="text"
                      value={manualHost}
                      onChange={(e) => setManualHost(e.target.value)}
                      placeholder={t('proxies.modal.add_proxy.host_placeholder')}
                      className="tf-input mt-1 w-full px-2.5 py-1.5 text-xs"
                    />
                  </div>
                  <div>
                    <label
                      htmlFor={`${manualFormId}-port`}
                      className="block text-[11px] text-tf-secondary"
                    >
                      {t('wizard.modal.step2_manual_port')}
                    </label>
                    <input
                      id={`${manualFormId}-port`}
                      type="number"
                      min={1}
                      max={UI_CONFIG.MAX_PORT}
                      value={manualPort}
                      onChange={(e) => {
                        setManualPort(e.target.value);
                        setManualPortError(null);
                      }}
                      className="tf-input mt-1 w-full px-2.5 py-1.5 text-xs"
                    />
                  </div>
                </div>
                {manualPortError && (
                  <p role="alert" className="text-xs font-semibold text-tf-red">
                    {manualPortError}
                  </p>
                )}
                <div className="grid grid-cols-3 gap-2.5">
                  <div>
                    <label
                      htmlFor={`${manualFormId}-name`}
                      className="block text-[11px] text-tf-secondary"
                    >
                      {t('wizard.modal.step2_manual_name')}
                    </label>
                    <input
                      id={`${manualFormId}-name`}
                      type="text"
                      value={manualName}
                      onChange={(e) => setManualName(e.target.value)}
                      className="tf-input mt-1 w-full px-2.5 py-1.5 text-xs"
                    />
                  </div>
                  <div>
                    <label
                      htmlFor={`${manualFormId}-user`}
                      className="block text-[11px] text-tf-secondary"
                    >
                      {t('wizard.modal.step2_manual_user')}
                    </label>
                    <input
                      id={`${manualFormId}-user`}
                      type="text"
                      value={manualUsername}
                      onChange={(e) => setManualUsername(e.target.value)}
                      className="tf-input mt-1 w-full px-2.5 py-1.5 text-xs"
                    />
                  </div>
                  <div>
                    <label
                      htmlFor={`${manualFormId}-pass`}
                      className="block text-[11px] text-tf-secondary"
                    >
                      {t('wizard.modal.step2_manual_pass')}
                    </label>
                    <input
                      id={`${manualFormId}-pass`}
                      type="password"
                      value={manualPassword}
                      onChange={(e) => setManualPassword(e.target.value)}
                      className="tf-input mt-1 w-full px-2.5 py-1.5 text-xs"
                    />
                  </div>
                </div>
              </div>
            )}

            {onTestProxy &&
              !enabledExistingProxies[0] &&
              ((proxyInputMode === 'link' && Boolean(customUri.trim())) ||
                (proxyInputMode === 'manual' && Boolean(manualHost.trim()))) && (
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-tf-md border border-tf-border bg-tf-surface-alt p-2.5 text-xs">
                  <button
                    type="button"
                    disabled={testingExisting}
                    onClick={() => {
                      void handleTestProxyInWizard();
                    }}
                    className="tf-surface flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-cyan hover:border-tf-cyan disabled:opacity-60"
                  >
                    <Activity className="h-3.5 w-3.5" />
                    {testingExisting
                      ? t('dashboard.simple.testing_proxy')
                      : t('wizard.modal.step2_test_button')}
                  </button>
                  {existingTestFeedback && (
                    <span
                      className={`text-[11px] font-semibold ${
                        existingTestFeedback.ok ? 'text-tf-green' : 'text-tf-red'
                      }`}
                    >
                      {existingTestFeedback.ok
                        ? t('wizard.modal.step2_test_ok', {
                            ms: existingTestFeedback.ms
                          })
                        : t('wizard.modal.step2_test_failed')}
                    </span>
                  )}
                </div>
              )}
          </div>
        )}

        {/* Step 3: Interface Experience Mode */}
        {step === 3 && (
          <div className="mt-5 space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-tf-accent">
              {t('wizard.modal.step3_title')}
            </h3>

            <button
              type="button"
              onClick={() => setSelectedMode('simple')}
              className={`flex w-full items-start gap-3.5 rounded-tf-md border p-4 text-left transition ${
                selectedMode === 'simple'
                  ? 'border-tf-green bg-tf-green/10'
                  : 'border-tf-border bg-tf-surface-alt'
              }`}
            >
              <Sparkles className="mt-0.5 h-5 w-5 shrink-0 text-tf-green" />
              <div className="flex-1">
                <div className="text-xs font-bold text-tf-primary">
                  {t('wizard.modal.step3_simple_title')}
                </div>
                <div className="mt-1 text-[11px] text-tf-secondary">
                  {t('wizard.modal.step3_simple_desc')}
                </div>
              </div>
              {selectedMode === 'simple' && (
                <CheckCircle2 className="h-4 w-4 text-tf-green" />
              )}
            </button>

            <button
              type="button"
              onClick={() => setSelectedMode('expert')}
              className={`flex w-full items-start gap-3.5 rounded-tf-md border p-4 text-left transition ${
                selectedMode === 'expert'
                  ? 'border-tf-cyan bg-tf-cyan/10'
                  : 'border-tf-border bg-tf-surface-alt'
              }`}
            >
              <Terminal className="mt-0.5 h-5 w-5 shrink-0 text-tf-cyan" />
              <div className="flex-1">
                <div className="text-xs font-bold text-tf-primary">
                  {t('wizard.modal.step3_expert_title')}
                </div>
                <div className="mt-1 text-[11px] text-tf-secondary">
                  {t('wizard.modal.step3_expert_desc')}
                </div>
              </div>
              {selectedMode === 'expert' && (
                <CheckCircle2 className="h-4 w-4 text-tf-cyan" />
              )}
            </button>

            <div className="rounded-tf-md border border-tf-border bg-tf-surface-alt p-3 text-xs">
              <div className="font-bold text-tf-primary">
                {t('wizard.modal.step3_summary_title')}
              </div>
              <p className="mt-1 text-[11px] text-tf-secondary">
                {hasPlannedProxy
                  ? t('wizard.modal.step3_summary_with_proxy')
                  : t('wizard.modal.step3_summary_direct')}
              </p>
              {onEnableProtection && (
                <label
                  htmlFor={`${manualFormId}-enable-now`}
                  className="mt-2.5 flex cursor-pointer items-center gap-2 border-t border-tf-border pt-2.5 text-xs font-semibold text-tf-primary"
                >
                  <input
                    id={`${manualFormId}-enable-now`}
                    type="checkbox"
                    checked={enableProtectionNow}
                    onChange={(e) => setEnableProtectionNow(e.target.checked)}
                    className="h-4 w-4 cursor-pointer accent-tf-accent"
                  />
                  <span>{t('wizard.modal.step3_enable_now')}</span>
                </label>
              )}
            </div>
          </div>
        )}

        {/* Footer Controls */}
        <div className="mt-6 flex items-center justify-between border-t border-tf-border pt-4">
          {step > 1 ? (
            <button
              type="button"
              onClick={() => setStep((s) => s - 1)}
              className="tf-surface-alt px-4 py-2 text-xs font-semibold text-tf-secondary hover:text-tf-primary"
            >
              {t('wizard.modal.back')}
            </button>
          ) : (
            <div />
          )}

          {step < TOTAL_WIZARD_STEPS ? (
            <button
              type="button"
              onClick={() => setStep((s) => s + 1)}
              className="tf-btn-accent px-5 py-2 text-xs font-bold"
            >
              {t('wizard.modal.next')}
            </button>
          ) : (
            <button
              type="button"
              disabled={applying}
              onClick={() => {
                void applySelectedGoalRules();
              }}
              className="tf-btn-accent flex items-center gap-2 px-5 py-2 text-xs font-bold disabled:cursor-not-allowed disabled:opacity-50"
            >
              <CheckCircle2 className="h-4 w-4" />
              {t('wizard.modal.finish')}
            </button>
          )}
        </div>
      </div>
    </ModalContainer>
  );
};
