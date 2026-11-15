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
  Briefcase,
  CheckCircle2,
  Gamepad2,
  Shield,
  Sparkles,
  Terminal,
  Wand2,
  X
} from 'lucide-react';
import { ModalContainer } from './ModalContainer';
import { SYSTEM_CONSTANTS } from '../config/constants';
import {
  ProxyChain,
  ProxyNode,
  RoutingRule,
  TransportProtocol
} from '../types/routeward';

export type ExperienceMode = 'simple' | 'expert';
type GoalProfile = 'privacy' | 'work' | 'gaming';

interface QuickSetupWizardModalProps {
  proxies: ProxyNode[];
  chains: ProxyChain[];
  currentMode: ExperienceMode;
  onImportUris: (
    uriText: string
  ) => Promise<ProxyNode[] | number | void> | void;
  onAddRule: (rule: RoutingRule) => Promise<unknown> | void;
  onSelectMode: (mode: ExperienceMode) => void;
  onComplete: (hasEnabledProxy?: boolean) => void;
  onClose: () => void;
}

const TOTAL_WIZARD_STEPS = 3;

export const QuickSetupWizardModal: React.FC<QuickSetupWizardModalProps> = ({
  proxies,
  chains,
  currentMode,
  onImportUris,
  onAddRule,
  onSelectMode,
  onComplete,
  onClose
}) => {
  const { t } = useTranslation();
  const titleId = useId();
  const [step, setStep] = useState(1);
  const [goal, setGoal] = useState<GoalProfile>('privacy');
  const [customUri, setCustomUri] = useState('');
  const [selectedMode, setSelectedMode] = useState<ExperienceMode>(currentMode);
  const [applying, setApplying] = useState(false);

  const enabledExistingProxies = proxies.filter((p) => p.enabled);

  const applySelectedGoalRules = async () => {
    if (applying) return;
    setApplying(true);
    try {
      let postImportProxies = proxies;
      if (customUri.trim()) {
        const importResult = await onImportUris(customUri.trim());
        if (Array.isArray(importResult)) {
          postImportProxies = importResult;
        }
      }

      const enabledProxies = postImportProxies.filter((p) => p.enabled);
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
            : ['preset-rfc1918-direct'];

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
          targetId = primaryProxyId;
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
      onComplete(hasEnabledProxy);
      onClose();
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
              <div className="tf-surface-alt flex items-center justify-between p-3.5 text-xs">
                <div>
                  <div className="font-bold text-tf-primary">
                    {t('wizard.modal.step2_use_existing')}
                  </div>
                  <div className="mt-0.5 font-mono text-[11px] text-tf-cyan">
                    {`${enabledExistingProxies[0].name} (${enabledExistingProxies[0].protocol.toUpperCase()} - ${enabledExistingProxies[0].host}:${enabledExistingProxies[0].port})`}
                  </div>
                </div>
                <CheckCircle2 className="h-5 w-5 text-tf-green" />
              </div>
            ) : (
              <div className="rounded-tf-md border border-tf-cyan/30 bg-tf-cyan/10 p-3.5 text-xs">
                <div className="font-bold text-tf-primary">
                  {t('wizard.modal.step2_no_proxy_title')}
                </div>
                <p className="mt-1 text-[11px] text-tf-secondary">
                  {t('wizard.modal.step2_no_proxy_desc')}
                </p>
              </div>
            )}

            <div>
              <label className="mb-1.5 block text-xs font-medium text-tf-secondary">
                {t('wizard.modal.step2_paste_uri')}
              </label>
              <textarea
                rows={3}
                value={customUri}
                onChange={(e) => setCustomUri(e.target.value)}
                placeholder={t('wizard.modal.step2_uri_placeholder')}
                className="tf-input w-full p-2.5 font-mono text-xs"
              />
            </div>
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
