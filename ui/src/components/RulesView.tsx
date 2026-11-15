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
  ArrowDown,
  ArrowUp,
  Ban,
  CheckCircle2,
  Code2,
  Edit3,
  Gamepad2,
  Globe,
  MessageSquare,
  Music,
  Plus,
  Shield,
  ShieldAlert,
  Sparkles,
  Trash2
} from 'lucide-react';
import { SYSTEM_CONSTANTS, UI_CONFIG } from '../config/constants';
import { generateClientId } from '../services/ipc';
import {
  ConnectionRequest,
  PortRange,
  ProxyChain,
  ProxyNode,
  RoutingRule,
  RuleAction,
  RuleEvaluationResult,
  TransportProtocol
} from '../types/routeward';
import { ExperienceMode } from './QuickSetupWizardModal';
import { ModalContainer } from './ModalContainer';

interface RulesViewProps {
  rules: RoutingRule[];
  proxies: ProxyNode[];
  chains: ProxyChain[];
  experienceMode: ExperienceMode;
  onEvaluateRule: (
    req: ConnectionRequest
  ) => Promise<RuleEvaluationResult | null>;
  onAddRule: (rule: RoutingRule) => void;
  onToggleRule: (ruleId: string) => void;
  onReorderRule: (ruleId: string, direction: 'up' | 'down') => void;
  onRemoveRule: (id: string) => void;
}

function parsePortSpec(spec: string): PortRange[] {
  const ranges: PortRange[] = [];
  for (const part of spec.split(',')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    if (trimmed.includes('-')) {
      const [s, e] = trimmed.split('-').map((n) => Number(n.trim()));
      if (!Number.isNaN(s) && !Number.isNaN(e)) {
        ranges.push({ start: s, end: e });
      }
    } else {
      const p = Number(trimmed);
      if (!Number.isNaN(p) && p > 0) {
        ranges.push({ start: p, end: p });
      }
    }
  }
  return ranges;
}

function formatPortSpec(ranges: PortRange[]): string {
  return ranges
    .map((r) => (r.start === r.end ? `${r.start}` : `${r.start}-${r.end}`))
    .join(', ');
}

function requiresAdvancedEditor(rule: RoutingRule): boolean {
  const hasProcesses = rule.processPatterns.length > 0;
  const hasDomains = rule.domainPatterns.length > 0;
  return (
    rule.ipCidrs.length > 0 ||
    rule.portRanges.length > 0 ||
    rule.protocol !== 'any' ||
    rule.action.type === 'chain' ||
    (hasProcesses && hasDomains) ||
    (!hasProcesses && !hasDomains)
  );
}

export const RulesView: React.FC<RulesViewProps> = ({
  rules,
  proxies,
  chains,
  experienceMode,
  onEvaluateRule,
  onAddRule,
  onToggleRule,
  onReorderRule,
  onRemoveRule
}) => {
  const { t } = useTranslation();
  const addRuleModalTitleId = useId();

  // Simulator state
  const [simProc, setSimProc] = useState('firefox.exe');
  const [simHost, setSimHost] = useState('198.18.0.2');
  const [simPort, setSimPort] = useState<number>(UI_CONFIG.DEFAULT_TEST_PORT);
  const [simResult, setSimResult] = useState<RuleEvaluationResult | null>(null);

  // Add / Edit Rule & Presets modal state
  const [showModal, setShowModal] = useState(false);
  const [showPresets, setShowPresets] = useState(false);
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [editingRuleEnabled, setEditingRuleEnabled] = useState(true);
  const [editingRequiresAdvanced, setEditingRequiresAdvanced] = useState(false);
  const [ruleName, setRuleName] = useState('');
  const [priority, setPriority] = useState<number>(
    UI_CONFIG.DEFAULT_RULE_PRIORITY
  );
  const [processesText, setProcessesText] = useState('');
  const [domainsText, setDomainsText] = useState('');
  const [cidrsText, setCidrsText] = useState('');
  const [portsText, setPortsText] = useState('');
  const [protocol, setProtocol] = useState<TransportProtocol>('any');
  const [actionType, setActionType] = useState<RuleAction['type']>('proxy');
  const [actionTargetId, setActionTargetId] = useState(proxies[0]?.id || '');
  const [simpleTargetType, setSimpleTargetType] = useState<'app' | 'site'>('app');
  const [simpleTargetValue, setSimpleTargetValue] = useState('');
  const [showAdvancedFields, setShowAdvancedFields] = useState(false);

  const openCreateRuleModal = () => {
    setEditingRuleId(null);
    setEditingRuleEnabled(true);
    setEditingRequiresAdvanced(false);
    setRuleName('');
    setPriority(UI_CONFIG.DEFAULT_RULE_PRIORITY);
    setProcessesText('');
    setDomainsText('');
    setCidrsText('');
    setPortsText('');
    setProtocol('any');
    setActionType('proxy');
    setActionTargetId(proxies[0]?.id || '');
    setSimpleTargetType('app');
    setSimpleTargetValue('');
    setShowAdvancedFields(false);
    setShowModal(true);
  };

  const openEditRuleModal = (rule: RoutingRule) => {
    const needsAdvanced = requiresAdvancedEditor(rule);
    const hasDomainsOnly =
      rule.domainPatterns.length > 0 && rule.processPatterns.length === 0;
    setEditingRuleId(rule.id);
    setEditingRuleEnabled(rule.enabled);
    setEditingRequiresAdvanced(needsAdvanced);
    setRuleName(rule.name);
    setPriority(rule.priority);
    setProcessesText(rule.processPatterns.join(', '));
    setDomainsText(rule.domainPatterns.join(', '));
    setCidrsText(rule.ipCidrs.join(', '));
    setPortsText(formatPortSpec(rule.portRanges));
    setProtocol(rule.protocol);
    setActionType(rule.action.type);
    setActionTargetId(
      rule.action.targetId ||
        (rule.action.type === 'chain' ? chains[0]?.id || '' : proxies[0]?.id || '')
    );
    setSimpleTargetType(hasDomainsOnly ? 'site' : 'app');
    setSimpleTargetValue(
      hasDomainsOnly
        ? rule.domainPatterns.join(', ')
        : rule.processPatterns.join(', ')
    );
    setShowAdvancedFields(needsAdvanced);
    setShowModal(true);
  };

  const closeRuleModal = () => {
    setEditingRuleId(null);
    setEditingRuleEnabled(true);
    setEditingRequiresAdvanced(false);
    setShowAdvancedFields(false);
    setShowModal(false);
  };

  const handleRunSimulator = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await onEvaluateRule({
      processName: simProc,
      targetHost: simHost,
      targetPort: simPort,
      protocol: 'tcp'
    });
    setSimResult(res);
  };

  const handleApplyPreset = (
    preset: (typeof SYSTEM_CONSTANTS.rulePresets)[number]
  ) => {
    const actType = preset.suggestedActionType as RuleAction['type'];
    const targetId =
      actType === 'proxy'
        ? proxies[0]?.id
        : actType === 'chain'
          ? chains[0]?.id
          : undefined;

    onAddRule({
      id: `${generateClientId('rule')}-${preset.id}`,
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
    setShowPresets(false);
  };

  const handleSetVisualAppAction = (
    appCard: (typeof SYSTEM_CONSTANTS.visualAppCatalog)[number],
    chosenAction: 'proxy' | 'direct' | 'block'
  ) => {
    const primaryProxyId = proxies[0]?.id || 'proxy-socks5-primary';
    onAddRule({
      id: `rule-visual-${appCard.id}`,
      name: t(`${appCard.i18nKey}.name`),
      enabled: true,
      priority: appCard.priority,
      processPatterns: [...appCard.processPatterns],
      domainPatterns: [],
      ipCidrs: [],
      portRanges: [],
      protocol: 'any',
      action:
        chosenAction === 'proxy'
          ? { type: 'proxy', targetId: primaryProxyId }
          : { type: chosenAction }
    });
  };

  const resolveVisualAppIcon = (iconName: string) => {
    switch (iconName) {
      case 'globe':
        return Globe;
      case 'message':
        return MessageSquare;
      case 'gamepad':
        return Gamepad2;
      case 'code':
        return Code2;
      case 'music':
        return Music;
      default:
        return ShieldAlert;
    }
  };

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault();
    const splitList = (raw: string) =>
      raw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

    const isSimpleSubmit = experienceMode === 'simple' && !showAdvancedFields;
    const effectiveName = isSimpleSubmit
      ? ruleName.trim() || simpleTargetValue.trim()
      : ruleName.trim();
    if (!effectiveName) return;

    const effectiveProcesses = isSimpleSubmit
      ? simpleTargetType === 'app'
        ? splitList(simpleTargetValue)
        : []
      : splitList(processesText);
    const effectiveDomains = isSimpleSubmit
      ? simpleTargetType === 'site'
        ? splitList(simpleTargetValue)
        : []
      : splitList(domainsText);

    onAddRule({
      id: editingRuleId ?? generateClientId('rule'),
      name: effectiveName,
      enabled: editingRuleId ? editingRuleEnabled : true,
      priority: isSimpleSubmit
        ? editingRuleId
          ? priority
          : UI_CONFIG.DEFAULT_RULE_PRIORITY
        : priority,
      processPatterns: effectiveProcesses,
      domainPatterns: effectiveDomains,
      ipCidrs: isSimpleSubmit ? [] : splitList(cidrsText),
      portRanges: isSimpleSubmit ? [] : parsePortSpec(portsText),
      protocol: isSimpleSubmit ? 'any' : protocol,
      action:
        actionType === 'proxy' || actionType === 'chain'
          ? { type: actionType, targetId: actionTargetId || proxies[0]?.id || '' }
          : { type: actionType }
    });
    setRuleName('');
    setSimpleTargetValue('');
    closeRuleModal();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-bold text-tf-primary">
            {experienceMode === 'simple'
              ? t('rules.simple.title')
              : t('rules.header.title')}
          </h2>
          <p className="text-xs text-tf-secondary">
            {experienceMode === 'simple'
              ? t('rules.simple.subtitle')
              : t('rules.header.subtitle')}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {experienceMode === 'expert' && (
            <button
              onClick={() => setShowPresets((prev) => !prev)}
              className="tf-surface-alt flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-tf-accent hover:border-tf-accent"
            >
              <Sparkles className="h-3.5 w-3.5" />
              {t('rules.header.presets_button')}
            </button>
          )}
          <button
            onClick={openCreateRuleModal}
            className="tf-btn-accent flex items-center gap-1.5 px-3.5 py-2 text-xs"
          >
            <Plus className="h-3.5 w-3.5" />
            {experienceMode === 'simple'
              ? t('rules.simple.add_button')
              : t('rules.header.add_button')}
          </button>
        </div>
      </div>

      {/* 1-Click Rule Templates Gallery (Expert mode) */}
      {experienceMode === 'expert' && showPresets && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {SYSTEM_CONSTANTS.rulePresets.map((preset) => (
            <button
              key={preset.id}
              onClick={() => handleApplyPreset(preset)}
              className="tf-card flex flex-col justify-between p-4 text-left transition hover:border-tf-accent"
            >
              <div>
                <div className="flex items-center justify-between">
                  <Sparkles className="h-4 w-4 text-tf-accent" />
                  <span className="rounded bg-tf-surface-alt px-2 py-0.5 font-mono text-[10px] font-bold uppercase text-tf-accent">
                    #{preset.priority} • {preset.suggestedActionType}
                  </span>
                </div>
                <div className="mt-2 text-xs font-bold text-tf-primary">
                  {t(`${preset.i18nKey}.name`)}
                </div>
                <p className="mt-1 text-[11px] text-tf-secondary">
                  {t(`${preset.i18nKey}.desc`)}
                </p>
              </div>
              <div className="mt-3 text-[11px] font-semibold text-tf-accent">
                + {t('rules.header.add_button')}
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Visual App Routing Cards ("Mes Applications" - Always available, highlighted for beginners) */}
      <div className="tf-card space-y-4 p-5">
        <div>
          <h3 className="text-sm font-bold text-tf-primary">
            {t('rules.visual_apps.section_title')}
          </h3>
          <p className="text-xs text-tf-secondary">
            {t('rules.visual_apps.section_subtitle')}
          </p>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {SYSTEM_CONSTANTS.visualAppCatalog.map((appCard) => {
            const Icon = resolveVisualAppIcon(appCard.icon);
            const existingRule = rules.find(
              (r) => r.id === `rule-visual-${appCard.id}`
            );
            const activeAction =
              existingRule?.action.type ||
              (appCard.defaultAction as 'proxy' | 'direct' | 'block');

            return (
              <div
                key={appCard.id}
                className="tf-surface-alt flex flex-col justify-between space-y-3 p-4"
              >
                <div className="flex items-start gap-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-tf-md bg-tf-accent/15 text-tf-accent">
                    <Icon className="h-5 w-5" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-tf-primary">
                      {t(`${appCard.i18nKey}.name`)}
                    </div>
                    <div className="mt-0.5 text-[11px] text-tf-secondary">
                      {t(`${appCard.i18nKey}.desc`)}
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-1.5 pt-1">
                  <button
                    type="button"
                    onClick={() => handleSetVisualAppAction(appCard, 'proxy')}
                    className={`rounded px-2 py-1.5 text-[11px] font-bold transition ${
                      activeAction === 'proxy'
                        ? 'bg-tf-accent text-tf-bg'
                        : 'bg-tf-bg text-tf-secondary hover:text-tf-primary'
                    }`}
                  >
                    {t('rules.visual_apps.action_proxy')}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleSetVisualAppAction(appCard, 'direct')}
                    className={`rounded px-2 py-1.5 text-[11px] font-bold transition ${
                      activeAction === 'direct'
                        ? 'bg-tf-green text-tf-bg'
                        : 'bg-tf-bg text-tf-secondary hover:text-tf-primary'
                    }`}
                  >
                    {t('rules.visual_apps.action_direct')}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleSetVisualAppAction(appCard, 'block')}
                    className={`flex items-center justify-center gap-1 rounded px-2 py-1.5 text-[11px] font-bold transition ${
                      activeAction === 'block'
                        ? 'bg-tf-red text-tf-bg'
                        : 'bg-tf-bg text-tf-secondary hover:text-tf-primary'
                    }`}
                  >
                    <Ban className="h-3 w-3" />
                    {t('rules.visual_apps.action_block')}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Live Rule Simulator (Expert Mode) */}
      {experienceMode === 'expert' && (
        <form onSubmit={handleRunSimulator} className="tf-card space-y-3 p-4">
        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-tf-accent">
          <Shield className="h-4 w-4" />
          <span>{t('rules.simulator.title')}</span>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
          <input
            type="text"
            value={simProc}
            onChange={(e) => setSimProc(e.target.value)}
            placeholder={t('rules.simulator.process_placeholder')}
            aria-label={t('rules.simulator.process_placeholder')}
            className="tf-input px-3 py-1.5 text-xs"
          />
          <input
            type="text"
            value={simHost}
            onChange={(e) => setSimHost(e.target.value)}
            placeholder={t('rules.simulator.host_placeholder')}
            aria-label={t('rules.simulator.host_placeholder')}
            className="tf-input px-3 py-1.5 text-xs"
          />
          <input
            type="number"
            value={simPort}
            onChange={(e) => setSimPort(Number(e.target.value))}
            placeholder={t('rules.simulator.port_placeholder')}
            aria-label={t('rules.simulator.port_placeholder')}
            className="tf-input px-3 py-1.5 text-xs"
          />
          <button type="submit" className="tf-btn-accent py-1.5 text-xs">
            {t('rules.simulator.test_button')}
          </button>
        </div>
        {simResult && (
          <div className="tf-surface-alt flex flex-wrap items-center gap-4 px-3 py-2 text-xs">
            <span className="flex items-center gap-1.5 font-semibold text-tf-green">
              <CheckCircle2 className="h-4 w-4" />
              {t('rules.simulator.matched_rule')}:{' '}
              <span className="text-tf-primary">
                {simResult.matchedRuleName}
              </span>
            </span>
            <span className="font-mono text-tf-accent">
              {t('rules.simulator.resulting_action')}:{' '}
              {simResult.action.type.toUpperCase()}{' '}
              {simResult.action.targetId
                ? `(${simResult.action.targetId})`
                : ''}
            </span>
            {simResult.resolvedFromFakeIp && simResult.effectiveDomain && (
              <span className="rounded bg-tf-cyan/20 px-2 py-0.5 font-mono text-[11px] text-tf-cyan">
                {t('rules.simulator.fake_ip_resolved')}:{' '}
                {simResult.effectiveDomain}
              </span>
            )}
          </div>
        )}
      </form>
      )}

      {/* Simplified Custom Rules List (Simple) vs Full Priority Table (Expert) */}
      {experienceMode === 'simple' ? (
        <div className="tf-card space-y-3 p-5">
          <h3 className="text-sm font-bold text-tf-primary">
            {t('rules.simple.custom_rules_title')}
          </h3>
          {rules.length === 0 ? (
            <p className="py-4 text-center text-xs text-tf-secondary">
              {t('rules.simple.custom_rules_empty')}
            </p>
          ) : (
            <div className="divide-y divide-tf-border">
              {rules.map((rule) => {
                const targets = [
                  ...rule.processPatterns,
                  ...rule.domainPatterns,
                  ...rule.ipCidrs
                ];
                return (
                  <div
                    key={rule.id}
                    className={`flex flex-wrap items-center justify-between gap-3 py-3 ${
                      !rule.enabled ? 'opacity-50' : ''
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={() => onToggleRule(rule.id)}
                        aria-label={`${t('rules.table.enabled.toggle_aria')}: ${rule.name}`}
                        className="h-4 w-4 cursor-pointer accent-tf-accent"
                      />
                      <div>
                        <div className="text-xs font-bold text-tf-primary">
                          {rule.name}
                        </div>
                        <div className="font-mono text-[11px] text-tf-secondary">
                          {targets.length > 0
                            ? targets.join(', ')
                            : t('rules.table.targets.any')}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded px-2.5 py-0.5 text-[11px] font-bold ${
                          rule.action.type === 'block'
                            ? 'bg-tf-red/20 text-tf-red'
                            : rule.action.type === 'direct'
                              ? 'bg-tf-green/20 text-tf-green'
                              : 'bg-tf-accent/20 text-tf-accent'
                        }`}
                      >
                        {t(`rules.table.action.${rule.action.type}`)}
                      </span>
                      <button
                        type="button"
                        onClick={() => openEditRuleModal(rule)}
                        className="rounded p-1 text-tf-secondary hover:text-tf-accent"
                        title={t('rules.table.controls.edit')}
                        aria-label={`${t('rules.table.controls.edit')}: ${rule.name}`}
                      >
                        <Edit3 className="h-3.5 w-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={() => onRemoveRule(rule.id)}
                        className="rounded p-1 text-tf-secondary hover:text-tf-red"
                        title={t('rules.table.controls.delete')}
                        aria-label={`${t('rules.table.controls.delete')}: ${rule.name}`}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      ) : (
        <div className="tf-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-tf-border bg-tf-surface-alt text-[11px] uppercase tracking-wider text-tf-secondary">
                <tr>
                  <th className="px-4 py-3">
                    {t('rules.table.enabled.header')}
                  </th>
                  <th className="px-4 py-3">
                    {t('rules.table.priority.header')}
                  </th>
                  <th className="px-4 py-3">{t('rules.table.name.header')}</th>
                  <th className="px-4 py-3">
                    {t('rules.table.processes.header')}
                  </th>
                  <th className="px-4 py-3">{t('rules.table.targets.header')}</th>
                  <th className="px-4 py-3">{t('rules.table.ports.header')}</th>
                  <th className="px-4 py-3">{t('rules.table.action.header')}</th>
                  <th className="px-4 py-3">
                    {t('rules.table.controls.header')}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-tf-border">
                {rules.map((rule, idx) => (
                  <tr
                    key={rule.id}
                    className={`transition hover:bg-tf-surface-alt/50 ${
                      !rule.enabled ? 'opacity-50' : ''
                    }`}
                  >
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={() => onToggleRule(rule.id)}
                        aria-label={`${t('rules.table.enabled.toggle_aria')}: ${rule.name}`}
                        className="h-4 w-4 cursor-pointer accent-tf-accent"
                      />
                    </td>
                    <td className="px-4 py-3 font-mono font-bold text-tf-accent">
                      #{rule.priority}
                    </td>
                    <td className="px-4 py-3 font-semibold text-tf-primary">
                      {rule.name}
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-tf-secondary">
                      {rule.processPatterns.length > 0
                        ? rule.processPatterns.join(', ')
                        : t('rules.table.processes.any')}
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-tf-secondary">
                      {[...rule.domainPatterns, ...rule.ipCidrs].length > 0
                        ? [...rule.domainPatterns, ...rule.ipCidrs].join(', ')
                        : t('rules.table.targets.any')}
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-tf-secondary">
                      {rule.portRanges.length > 0
                        ? rule.portRanges
                            .map((r) =>
                              r.start === r.end
                                ? `${r.start}`
                                : `${r.start}-${r.end}`
                            )
                            .join(', ')
                        : t('rules.table.ports.any')}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`rounded px-2 py-0.5 font-mono text-[11px] font-bold ${
                          rule.action.type === 'block'
                            ? 'bg-tf-red/20 text-tf-red'
                            : rule.action.type === 'direct'
                              ? 'bg-tf-green/20 text-tf-green'
                              : 'bg-tf-accent/20 text-tf-accent'
                        }`}
                      >
                        {t(`rules.table.action.${rule.action.type}`)}
                        {rule.action.targetId ? ` -> ${rule.action.targetId}` : ''}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <button
                          disabled={idx === 0}
                          onClick={() => onReorderRule(rule.id, 'up')}
                          className="rounded p-1 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary disabled:opacity-30"
                          title={t('rules.table.controls.move_up')}
                          aria-label={`${t('rules.table.controls.move_up')}: ${rule.name}`}
                        >
                          <ArrowUp className="h-3.5 w-3.5" />
                        </button>
                        <button
                          disabled={idx === rules.length - 1}
                          onClick={() => onReorderRule(rule.id, 'down')}
                          className="rounded p-1 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary disabled:opacity-30"
                          title={t('rules.table.controls.move_down')}
                          aria-label={`${t('rules.table.controls.move_down')}: ${rule.name}`}
                        >
                          <ArrowDown className="h-3.5 w-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => openEditRuleModal(rule)}
                          className="rounded p-1 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-accent"
                          title={t('rules.table.controls.edit')}
                          aria-label={`${t('rules.table.controls.edit')}: ${rule.name}`}
                        >
                          <Edit3 className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => onRemoveRule(rule.id)}
                          className="rounded p-1 text-tf-secondary hover:text-tf-red"
                          title={t('rules.table.controls.delete')}
                          aria-label={`${t('rules.table.controls.delete')}: ${rule.name}`}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Add / Edit Rule Modal */}
      {showModal && (
        <ModalContainer
          labelledBy={addRuleModalTitleId}
          onClose={closeRuleModal}
        >
          <form
            onSubmit={handleCreateRule}
            className="tf-card w-full max-w-lg space-y-3.5 p-6"
          >
            <h3
              id={addRuleModalTitleId}
              className="text-base font-bold text-tf-primary"
            >
              {editingRuleId
                ? t('rules.modal.add.edit_title')
                : experienceMode === 'simple'
                  ? t('rules.simple.add_button')
                  : t('rules.modal.add.title')}
            </h3>

            {experienceMode === 'simple' && !showAdvancedFields ? (
              <>
                <div className="flex gap-2">
                  <button
                    type="button"
                    aria-pressed={simpleTargetType === 'app'}
                    onClick={() => setSimpleTargetType('app')}
                    className={`flex-1 rounded-tf-md px-3 py-2 text-xs font-bold transition ${
                      simpleTargetType === 'app'
                        ? 'bg-tf-accent text-tf-bg'
                        : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
                    }`}
                  >
                    {t('rules.simple.type_app')}
                  </button>
                  <button
                    type="button"
                    aria-pressed={simpleTargetType === 'site'}
                    onClick={() => setSimpleTargetType('site')}
                    className={`flex-1 rounded-tf-md px-3 py-2 text-xs font-bold transition ${
                      simpleTargetType === 'site'
                        ? 'bg-tf-accent text-tf-bg'
                        : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
                    }`}
                  >
                    {t('rules.simple.type_site')}
                  </button>
                </div>

                <div>
                  <label
                    htmlFor="simple-rule-target"
                    className="block text-xs text-tf-secondary"
                  >
                    {simpleTargetType === 'app'
                      ? t('rules.simple.target_app_label')
                      : t('rules.simple.target_site_label')}
                  </label>
                  <input
                    id="simple-rule-target"
                    type="text"
                    required
                    value={simpleTargetValue}
                    onChange={(e) => setSimpleTargetValue(e.target.value)}
                    placeholder={
                      simpleTargetType === 'app'
                        ? t('rules.simple.target_app_placeholder')
                        : t('rules.simple.target_site_placeholder')
                    }
                    className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                  />
                </div>

                <div>
                  <label className="block text-xs text-tf-secondary">
                    {t('rules.simple.action_label')}
                  </label>
                  <div className="mt-1 grid grid-cols-3 gap-2">
                    {(
                      [
                        {
                          type: 'proxy' as const,
                          label: t('connections.simple.route_proxy'),
                          activeClass: 'bg-tf-accent text-tf-bg'
                        },
                        {
                          type: 'direct' as const,
                          label: t('connections.simple.route_direct'),
                          activeClass: 'bg-tf-green text-tf-bg'
                        },
                        {
                          type: 'block' as const,
                          label: t('connections.simple.route_blocked'),
                          activeClass: 'bg-tf-red text-tf-bg'
                        }
                      ]
                    ).map((opt) => (
                      <button
                        key={opt.type}
                        type="button"
                        aria-pressed={actionType === opt.type}
                        onClick={() => {
                          setActionType(opt.type);
                          if (opt.type === 'proxy' && !actionTargetId) {
                            setActionTargetId(proxies[0]?.id || '');
                          }
                        }}
                        className={`rounded-tf-md px-3 py-2 text-xs font-bold transition ${
                          actionType === opt.type
                            ? opt.activeClass
                            : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
                        }`}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => setShowAdvancedFields(true)}
                  className="text-xs font-semibold text-tf-cyan hover:underline"
                >
                  {t('rules.simple.show_advanced_options')}
                </button>
              </>
            ) : (
              <>
                {experienceMode === 'simple' && !editingRequiresAdvanced && (
                  <button
                    type="button"
                    onClick={() => setShowAdvancedFields(false)}
                    className="text-xs font-semibold text-tf-cyan hover:underline"
                  >
                    {t('rules.simple.hide_advanced_options')}
                  </button>
                )}
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <label className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.name_label')}
                </label>
                <input
                  type="text"
                  required
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.priority_label')}
                </label>
                <input
                  type="number"
                  required
                  value={priority}
                  onChange={(e) => setPriority(Number(e.target.value))}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs text-tf-secondary">
                {t('rules.modal.add.processes_label')}
              </label>
              <input
                type="text"
                value={processesText}
                onChange={(e) => setProcessesText(e.target.value)}
                className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.domains_label')}
                </label>
                <input
                  type="text"
                  value={domainsText}
                  onChange={(e) => setDomainsText(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.cidrs_label')}
                </label>
                <input
                  type="text"
                  value={cidrsText}
                  onChange={(e) => setCidrsText(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
            </div>

            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.ports_label')}
                </label>
                <input
                  type="text"
                  value={portsText}
                  onChange={(e) => setPortsText(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.protocol_label')}
                </label>
                <select
                  value={protocol}
                  onChange={(e) =>
                    setProtocol(e.target.value as TransportProtocol)
                  }
                  className="tf-input mt-1 w-full px-2 py-1.5 text-sm uppercase"
                >
                  <option value="any">ANY</option>
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.action_type_label')}
                </label>
                <select
                  value={actionType}
                  onChange={(e) => {
                    const nextType = e.target.value as RuleAction['type'];
                    setActionType(nextType);
                    if (nextType === 'proxy') {
                      setActionTargetId(proxies[0]?.id || '');
                    } else if (nextType === 'chain') {
                      setActionTargetId(chains[0]?.id || '');
                    }
                  }}
                  className="tf-input mt-1 w-full px-2 py-1.5 text-sm uppercase"
                >
                  <option value="proxy">PROXY</option>
                  <option value="chain">CHAIN</option>
                  <option value="direct">DIRECT</option>
                  <option value="block">BLOCK</option>
                </select>
              </div>
            </div>

            {(actionType === 'proxy' || actionType === 'chain') && (
              <div>
                <label className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.action_target_label')}
                </label>
                <select
                  value={actionTargetId}
                  onChange={(e) => setActionTargetId(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                >
                  {actionType === 'proxy'
                    ? proxies.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name} ({p.host}:{p.port})
                        </option>
                      ))
                    : chains.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name} ({c.proxyIds.length}{' '}
                          {t('proxies.section.chains.hops')})
                        </option>
                      ))}
                </select>
              </div>
            )}
              </>
            )}

            <div className="flex justify-end gap-2 pt-3">
              <button
                type="button"
                onClick={closeRuleModal}
                className="tf-surface-alt px-4 py-1.5 text-xs text-tf-secondary"
              >
                {t('rules.modal.add.cancel')}
              </button>
              <button
                type="submit"
                className="tf-btn-accent px-4 py-1.5 text-xs"
              >
                {t('rules.modal.add.submit')}
              </button>
            </div>
          </form>
        </ModalContainer>
      )}
    </div>
  );
};
