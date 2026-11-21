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

import React, { useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ArrowDown,
  ArrowUp,
  Ban,
  CheckCircle2,
  Code2,
  Edit3,
  FileCode2,
  FolderSearch,
  Gamepad2,
  Globe,
  MessageSquare,
  Music,
  Plus,
  Shield,
  ShieldAlert,
  Sparkles,
  Upload
} from 'lucide-react';
import { SYSTEM_CONSTANTS, UI_CONFIG } from '../config/constants';
import { generateClientId, routewardClient } from '../services/ipc';
import { normalizeDomainPatterns } from '../services/domain';
import { resolveSimpleProxyAction } from '../services/friendly';
import {
  ConnectionRequest,
  FoxyProxyImportResult,
  PortRange,
  ProxyChain,
  ProxyNode,
  RoutingRule,
  RuleAction,
  RuleEvaluationResult,
  SystemApplicationEntry,
  TransportProtocol
} from '../types/routeward';
import { ExperienceMode } from './QuickSetupWizardModal';
import { ModalContainer } from './ModalContainer';
import { ConfirmDeleteButton } from './ConfirmDeleteButton';

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
  onImportFoxyProxy?: (
    jsonText: string,
    processPatterns: string[]
  ) => Promise<FoxyProxyImportResult | null>;
  onListSystemApps?: () => Promise<SystemApplicationEntry[]>;
  onMissingProxy?: () => void;
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

function mergeCommaPattern(current: string, item: string): string {
  const existing = current
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (existing.some((entry) => entry.toLowerCase() === item.toLowerCase())) {
    return current;
  }
  return [...existing, item].join(', ');
}

function requiresAdvancedEditor(rule: RoutingRule): boolean {
  const hasProcesses = rule.processPatterns.length > 0;
  const hasDomains = rule.domainPatterns.length > 0;
  return (
    rule.ipCidrs.length > 0 ||
    rule.portRanges.length > 0 ||
    rule.protocol !== 'any' ||
    rule.action.type === 'chain' ||
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
  onRemoveRule,
  onImportFoxyProxy,
  onListSystemApps,
  onMissingProxy
}) => {
  const { t } = useTranslation();
  const addRuleModalTitleId = useId();
  const foxyModalTitleId = useId();
  const formId = useId();
  const foxyFileInputRef = useRef<HTMLInputElement | null>(null);

  const enabledProxies = proxies.filter((p) => p.enabled);
  const hasEnabledProxy = enabledProxies.length > 0;
  const enabledChains = hasEnabledProxy
    ? chains.filter(
        (c) =>
          c.enabled &&
          c.proxyIds.some((pid) => enabledProxies.some((p) => p.id === pid))
      )
    : [];
  const primaryEnabledProxyId = enabledProxies[0]?.id || '';

  // Simulator state
  const [simProc, setSimProc] = useState('firefox.exe');
  const [simHost, setSimHost] = useState('198.18.0.2');
  const [simPort, setSimPort] = useState<number>(UI_CONFIG.DEFAULT_TEST_PORT);
  const [simResult, setSimResult] = useState<RuleEvaluationResult | null>(null);

  // Add / Edit Rule & Presets modal state
  const [showModal, setShowModal] = useState(false);
  const [showPresets, setShowPresets] = useState(false);
  const [armedDeleteRuleId, setArmedDeleteRuleId] = useState<string | null>(null);
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
  const [actionType, setActionType] = useState<RuleAction['type']>(
    hasEnabledProxy ? 'proxy' : 'direct'
  );
  const [actionTargetId, setActionTargetId] = useState(primaryEnabledProxyId);
  const [simpleTargetType, setSimpleTargetType] = useState<'app' | 'site'>('app');
  const [simpleTargetValue, setSimpleTargetValue] = useState('');
  const [simpleOptionalDomains, setSimpleOptionalDomains] = useState('');
  const [simpleOptionalApps, setSimpleOptionalApps] = useState('');
  const [showAdvancedFields, setShowAdvancedFields] = useState(false);

  // System apps picker state
  const [showAppPicker, setShowAppPicker] = useState(false);
  const [loadingApps, setLoadingApps] = useState(false);
  const [systemApps, setSystemApps] = useState<SystemApplicationEntry[]>([]);
  const [detectedAppSearch, setDetectedAppSearch] = useState('');
  const [detectedAppsLoaded, setDetectedAppsLoaded] = useState(false);

  // FoxyProxy import modal state
  const [showFoxyProxyModal, setShowFoxyProxyModal] = useState(false);
  const [foxyJsonText, setFoxyJsonText] = useState('');
  const [foxyProcessFilter, setFoxyProcessFilter] = useState('msedge.exe');
  const [foxySubmitting, setFoxySubmitting] = useState(false);

  const fetchSystemAppsList = async () => {
    if (loadingApps) return;
    setLoadingApps(true);
    try {
      const fetcher =
        onListSystemApps ?? (() => routewardClient.listSystemApplications());
      const apps = await fetcher();
      setSystemApps(apps);
      setDetectedAppsLoaded(true);
    } finally {
      setLoadingApps(false);
    }
  };

  const loadSystemApps = async () => {
    setShowAppPicker((prev) => !prev);
    if (systemApps.length > 0 || loadingApps) return;
    await fetchSystemAppsList();
  };

  const handleSetDetectedAppAction = (
    app: SystemApplicationEntry,
    chosenAction: 'proxy' | 'direct' | 'block'
  ) => {
    const simpleProxyAction = resolveSimpleProxyAction(proxies, chains);
    if (chosenAction === 'proxy' && !simpleProxyAction) {
      onMissingProxy?.();
      return;
    }
    const slug = app.name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    onAddRule({
      id: `rule-app-${slug}`,
      name: app.name,
      enabled: true,
      priority: UI_CONFIG.DEFAULT_RULE_PRIORITY - 10,
      processPatterns: [app.name],
      domainPatterns: [],
      ipCidrs: [],
      portRanges: [],
      protocol: 'any',
      action:
        chosenAction === 'proxy' && simpleProxyAction
          ? simpleProxyAction
          : { type: chosenAction === 'proxy' ? 'direct' : chosenAction }
    });
  };

  const handleToggleProtectionPack = (
    pack: (typeof UI_CONFIG.SIMPLE_PROTECTION_PACKS)[number]
  ) => {
    const existing = rules.find((r) => r.id === pack.id);
    if (existing) {
      onToggleRule(existing.id);
      return;
    }
    onAddRule({
      id: pack.id,
      name: t(pack.titleKey),
      enabled: true,
      priority: pack.priority,
      processPatterns: [...pack.processPatterns],
      domainPatterns: [...pack.domainPatterns],
      ipCidrs: [],
      portRanges: [],
      protocol: 'any',
      action: { type: 'block' }
    });
  };

  const appendProcessPattern = (appName: string, mode: 'simple' | 'advanced') => {
    const current = mode === 'simple' ? simpleTargetValue : processesText;
    const next = mergeCommaPattern(current, appName);
    if (next !== current) {
      if (mode === 'simple') {
        setSimpleTargetValue(next);
      } else {
        setProcessesText(next);
      }
    }
    setShowAppPicker(false);
  };

  const handleSubmitFoxyProxy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!foxyJsonText.trim() || foxySubmitting) return;
    setFoxySubmitting(true);
    try {
      const procs = foxyProcessFilter
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const importer =
        onImportFoxyProxy ??
        ((json: string, patterns: string[]) =>
          routewardClient.importFoxyProxyJson(json, patterns));
      const res = await importer(foxyJsonText, procs);
      if (res) {
        setFoxyJsonText('');
        setShowFoxyProxyModal(false);
      }
    } finally {
      setFoxySubmitting(false);
    }
  };

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
    setActionType(hasEnabledProxy ? 'proxy' : 'direct');
    setActionTargetId(primaryEnabledProxyId);
    setSimpleTargetType('app');
    setSimpleTargetValue('');
    setSimpleOptionalDomains('');
    setSimpleOptionalApps('');
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
        (rule.action.type === 'chain'
          ? enabledChains[0]?.id || ''
          : primaryEnabledProxyId)
    );
    setSimpleTargetType(hasDomainsOnly ? 'site' : 'app');
    setSimpleTargetValue(
      hasDomainsOnly
        ? rule.domainPatterns.join(', ')
        : rule.processPatterns.join(', ')
    );
    setSimpleOptionalDomains(
      hasDomainsOnly ? '' : rule.domainPatterns.join(', ')
    );
    setSimpleOptionalApps(
      hasDomainsOnly ? rule.processPatterns.join(', ') : ''
    );
    setShowAdvancedFields(needsAdvanced);
    setShowModal(true);
  };

  const closeRuleModal = () => {
    setEditingRuleId(null);
    setEditingRuleEnabled(true);
    setEditingRequiresAdvanced(false);
    setShowAdvancedFields(false);
    setShowAppPicker(false);
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
    let actType = preset.suggestedActionType as RuleAction['type'];
    let targetId: string | undefined;
    if (actType === 'proxy') {
      targetId = primaryEnabledProxyId || undefined;
    } else if (actType === 'chain') {
      if (enabledChains[0]?.id) {
        targetId = enabledChains[0].id;
      } else if (primaryEnabledProxyId) {
        actType = 'proxy';
        targetId = primaryEnabledProxyId;
      }
    }

    if ((actType === 'proxy' || actType === 'chain') && !targetId) {
      onMissingProxy?.();
      return;
    }

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
    const simpleProxyAction = resolveSimpleProxyAction(proxies, chains);
    if (chosenAction === 'proxy' && !simpleProxyAction) {
      onMissingProxy?.();
      return;
    }
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
        chosenAction === 'proxy' && simpleProxyAction
          ? simpleProxyAction
          : { type: chosenAction === 'proxy' ? 'direct' : chosenAction }
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
    const effectiveProcesses = isSimpleSubmit
      ? simpleTargetType === 'app'
        ? splitList(simpleTargetValue)
        : splitList(simpleOptionalApps)
      : splitList(processesText);
    const normalizedSiteTarget = normalizeDomainPatterns(simpleTargetValue);
    const normalizedOptionalSites = normalizeDomainPatterns(simpleOptionalDomains);
    const effectiveDomains = isSimpleSubmit
      ? simpleTargetType === 'site'
        ? normalizedSiteTarget.patterns
        : normalizedOptionalSites.patterns
      : splitList(domainsText);

    const autoSimpleName =
      effectiveProcesses.length > 0 && effectiveDomains.length > 0
        ? `${effectiveProcesses[0]} (${effectiveDomains.join(', ')})`
        : simpleTargetType === 'site' && normalizedSiteTarget.primaryDomain
          ? normalizedSiteTarget.primaryDomain
          : simpleTargetValue.trim();

    const effectiveName = isSimpleSubmit
      ? ruleName.trim() || autoSimpleName
      : ruleName.trim();
    if (!effectiveName) return;

    let resolvedAction: RuleAction;
    if (actionType === 'proxy') {
      if (isSimpleSubmit) {
        const simpleProxyAction = resolveSimpleProxyAction(proxies, chains);
        if (!simpleProxyAction) {
          onMissingProxy?.();
          return;
        }
        resolvedAction = simpleProxyAction;
      } else {
        const targetId = enabledProxies.some((p) => p.id === actionTargetId)
          ? actionTargetId
          : primaryEnabledProxyId;
        if (!targetId) {
          onMissingProxy?.();
          return;
        }
        resolvedAction = { type: 'proxy', targetId };
      }
    } else if (actionType === 'chain') {
      const targetId = enabledChains.some((c) => c.id === actionTargetId)
        ? actionTargetId
        : enabledChains[0]?.id || '';
      if (!targetId) {
        onMissingProxy?.();
        return;
      }
      resolvedAction = { type: 'chain', targetId };
    } else {
      resolvedAction = { type: actionType };
    }

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
      action: resolvedAction
    });
    setRuleName('');
    setSimpleTargetValue('');
    setSimpleOptionalDomains('');
    setSimpleOptionalApps('');
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
        <div className="flex flex-wrap items-center gap-2">
          {experienceMode === 'expert' && (
            <>
              <button
                type="button"
                onClick={() => setShowFoxyProxyModal(true)}
                className="tf-surface-alt flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-tf-cyan hover:border-tf-cyan"
              >
                <FileCode2 className="h-3.5 w-3.5" />
                {t('rules.header.import_foxyproxy')}
              </button>
              <button
                type="button"
                onClick={() => setShowPresets((prev) => !prev)}
                className="tf-surface-alt flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-tf-accent hover:border-tf-accent"
              >
                <Sparkles className="h-3.5 w-3.5" />
                {t('rules.header.presets_button')}
              </button>
            </>
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
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
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
            const activeAction: 'proxy' | 'direct' | 'block' | null =
              existingRule?.enabled
                ? existingRule.action.type === 'chain'
                  ? hasEnabledProxy
                    ? 'proxy'
                    : 'direct'
                  : existingRule.action.type === 'proxy' && !hasEnabledProxy
                    ? 'direct'
                    : existingRule.action.type
                : null;

            return (
              <div
                key={appCard.id}
                className="tf-surface-alt flex flex-col justify-between space-y-3 p-4"
              >
                <div className="flex items-start gap-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-tf-md bg-tf-accent/15 text-tf-accent">
                    <Icon className="h-5 w-5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-xs font-bold text-tf-primary">
                      {t(`${appCard.i18nKey}.name`)}
                    </div>
                    <div className="mt-0.5 text-[11px] text-tf-secondary">
                      {t(`${appCard.i18nKey}.desc`)}
                    </div>
                    {activeAction === null && (
                      <div className="mt-1 inline-block rounded bg-tf-bg px-1.5 py-0.5 text-[10px] font-medium text-tf-secondary">
                        {t('rules.visual_apps.status_default')}
                      </div>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-1.5 pt-1">
                  <button
                    type="button"
                    aria-pressed={activeAction === 'proxy'}
                    onClick={() => handleSetVisualAppAction(appCard, 'proxy')}
                    className={`rounded px-2 py-2 text-[11px] font-bold transition ${
                      activeAction === 'proxy'
                        ? 'bg-tf-accent text-tf-bg'
                        : 'bg-tf-bg text-tf-secondary hover:text-tf-primary'
                    }`}
                  >
                    {t('rules.visual_apps.action_proxy')}
                  </button>
                  <button
                    type="button"
                    aria-pressed={activeAction === 'direct'}
                    onClick={() => handleSetVisualAppAction(appCard, 'direct')}
                    className={`rounded px-2 py-2 text-[11px] font-bold transition ${
                      activeAction === 'direct'
                        ? 'bg-tf-green text-tf-bg'
                        : 'bg-tf-bg text-tf-secondary hover:text-tf-primary'
                    }`}
                  >
                    {t('rules.visual_apps.action_direct')}
                  </button>
                  <button
                    type="button"
                    aria-pressed={activeAction === 'block'}
                    onClick={() => handleSetVisualAppAction(appCard, 'block')}
                    className={`flex items-center justify-center gap-1 rounded px-2 py-2 text-[11px] font-bold transition ${
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

      {/* 1-Click Protection Packs & Detected PC Apps (Simple mode) */}
      {experienceMode === 'simple' && (
        <>
          <div className="tf-card space-y-4 p-5">
            <div>
              <h3 className="text-sm font-bold text-tf-primary">
                {t('rules.simple.packs_title')}
              </h3>
              <p className="text-xs text-tf-secondary">
                {t('rules.simple.packs_subtitle')}
              </p>
            </div>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              {UI_CONFIG.SIMPLE_PROTECTION_PACKS.map((pack) => {
                const existing = rules.find((r) => r.id === pack.id);
                const active = Boolean(existing?.enabled);
                return (
                  <div
                    key={pack.id}
                    className={`tf-surface-alt flex items-start justify-between gap-3 p-4 ${
                      active ? 'border-tf-green/50 bg-tf-green/5' : ''
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="text-xs font-bold text-tf-primary">
                        {t(pack.titleKey)}
                      </div>
                      <p className="text-[11px] leading-relaxed text-tf-secondary">
                        {t(pack.descKey)}
                      </p>
                    </div>
                    <input
                      id={`${formId}-pack-${pack.id}`}
                      type="checkbox"
                      aria-label={t(pack.titleKey)}
                      checked={active}
                      onChange={() => handleToggleProtectionPack(pack)}
                      className="mt-0.5 h-4 w-4 shrink-0 cursor-pointer accent-tf-accent"
                    />
                  </div>
                );
              })}
            </div>
          </div>

          <div className="tf-card space-y-4 p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-tf-primary">
                  {t('rules.simple.detected_apps_title')}
                </h3>
                <p className="text-xs text-tf-secondary">
                  {t('rules.simple.detected_apps_subtitle')}
                </p>
              </div>
              <button
                type="button"
                disabled={loadingApps}
                onClick={() => {
                  void fetchSystemAppsList();
                }}
                className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-cyan hover:border-tf-cyan disabled:opacity-60"
              >
                <FolderSearch className="h-3.5 w-3.5" />
                {loadingApps
                  ? t('rules.modal.add.pick_app_loading')
                  : t('rules.simple.detected_apps_load')}
              </button>
            </div>

            {detectedAppsLoaded && (
              <>
                <input
                  id="simple-detected-apps-search"
                  type="text"
                  value={detectedAppSearch}
                  onChange={(e) => setDetectedAppSearch(e.target.value)}
                  placeholder={t('rules.simple.detected_apps_search')}
                  aria-label={t('rules.simple.detected_apps_search')}
                  className="tf-input w-full px-3 py-1.5 text-xs"
                />
                {systemApps.length === 0 ? (
                  <p className="py-3 text-center text-xs text-tf-secondary">
                    {t('rules.modal.add.pick_app_empty')}
                  </p>
                ) : (
                  <div className="grid max-h-64 grid-cols-1 gap-2 overflow-y-auto pr-1 sm:grid-cols-2">
                    {systemApps
                      .filter((app) =>
                        !detectedAppSearch.trim()
                          ? true
                          : app.name
                              .toLowerCase()
                              .includes(detectedAppSearch.trim().toLowerCase())
                      )
                      .slice(0, 24)
                      .map((app) => {
                        const slug = app.name
                          .toLowerCase()
                          .replace(/[^a-z0-9]+/g, '-');
                        const appRule = rules.find(
                          (r) =>
                            r.enabled &&
                            (r.id === `rule-app-${slug}` ||
                              (r.domainPatterns.length === 0 &&
                                r.processPatterns.some(
                                  (p) =>
                                    p.toLowerCase() === app.name.toLowerCase()
                                )))
                        );
                        const activeAppAction:
                          | 'proxy'
                          | 'direct'
                          | 'block'
                          | null = appRule
                          ? appRule.action.type === 'chain'
                            ? 'proxy'
                            : appRule.action.type
                          : null;
                        return (
                          <div
                            key={`${app.name}-${app.executablePath}`}
                            className="tf-surface-alt flex flex-wrap items-center justify-between gap-2 p-2.5 text-xs"
                          >
                            <div className="flex min-w-0 items-center gap-2">
                              <span className="truncate font-semibold text-tf-primary">
                                {app.name}
                              </span>
                              <span
                                className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold ${
                                  app.running
                                    ? 'bg-tf-green/20 text-tf-green'
                                    : 'bg-tf-surface text-tf-secondary'
                                }`}
                              >
                                {app.running
                                  ? t('rules.modal.add.pick_app_running')
                                  : t('rules.modal.add.pick_app_installed')}
                              </span>
                            </div>
                            <div className="flex shrink-0 items-center gap-1">
                              <button
                                type="button"
                                aria-pressed={activeAppAction === 'proxy'}
                                onClick={() =>
                                  handleSetDetectedAppAction(app, 'proxy')
                                }
                                className={`rounded px-2.5 py-1.5 text-[11px] font-bold transition ${
                                  activeAppAction === 'proxy'
                                    ? 'bg-tf-accent text-tf-bg'
                                    : 'bg-tf-accent/20 text-tf-accent hover:bg-tf-accent/30'
                                }`}
                              >
                                {t('connections.simple.route_proxy')}
                              </button>
                              <button
                                type="button"
                                aria-pressed={activeAppAction === 'direct'}
                                onClick={() =>
                                  handleSetDetectedAppAction(app, 'direct')
                                }
                                className={`rounded px-2.5 py-1.5 text-[11px] font-bold transition ${
                                  activeAppAction === 'direct'
                                    ? 'bg-tf-green text-tf-bg'
                                    : 'bg-tf-green/20 text-tf-green hover:bg-tf-green/30'
                                }`}
                              >
                                {t('connections.simple.route_direct')}
                              </button>
                              <button
                                type="button"
                                aria-pressed={activeAppAction === 'block'}
                                onClick={() =>
                                  handleSetDetectedAppAction(app, 'block')
                                }
                                className={`rounded px-2.5 py-1.5 text-[11px] font-bold transition ${
                                  activeAppAction === 'block'
                                    ? 'bg-tf-red text-tf-bg'
                                    : 'bg-tf-red/20 text-tf-red hover:bg-tf-red/30'
                                }`}
                              >
                                {t('connections.simple.route_blocked')}
                              </button>
                            </div>
                          </div>
                        );
                      })}
                  </div>
                )}
              </>
            )}
          </div>
        </>
      )}

      {/* Live Rule Simulator (Expert Mode) */}
      {experienceMode === 'expert' && (
        <form onSubmit={handleRunSimulator} className="tf-card space-y-3 p-4">
        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-tf-accent">
          <Shield className="h-4 w-4" />
          <span>{t('rules.simulator.title')}</span>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
          <input name="simulator-process"
            type="text"
            value={simProc}
            onChange={(e) => setSimProc(e.target.value)}
            placeholder={t('rules.simulator.process_placeholder')}
            aria-label={t('rules.simulator.process_placeholder')}
            className="tf-input px-3 py-1.5 text-xs"
          />
          <input name="simulator-host"
            type="text"
            value={simHost}
            onChange={(e) => setSimHost(e.target.value)}
            placeholder={t('rules.simulator.host_placeholder')}
            aria-label={t('rules.simulator.host_placeholder')}
            className="tf-input px-3 py-1.5 text-xs"
          />
          <input name="simulator-port"
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
                      <input name={`rule-enabled-${rule.id}`}
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
                        {rule.action.type === 'block'
                          ? t('rules.simple.action_badge_block')
                          : rule.action.type === 'direct'
                            ? t('rules.simple.action_badge_direct')
                            : rule.action.type === 'chain'
                              ? t('rules.simple.action_badge_chain')
                              : t('rules.simple.action_badge_proxy')}
                      </span>
                      <button
                        type="button"
                        onClick={() => openEditRuleModal(rule)}
                        className="rounded p-1.5 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-accent"
                        title={t('rules.table.controls.edit')}
                        aria-label={`${t('rules.table.controls.edit')}: ${rule.name}`}
                      >
                        <Edit3 className="h-3.5 w-3.5" />
                      </button>
                      <ConfirmDeleteButton
                        armed={armedDeleteRuleId === rule.id}
                        title={t('rules.table.controls.delete')}
                        ariaLabel={`${t('rules.table.controls.delete')}: ${rule.name}`}
                        onArm={() => setArmedDeleteRuleId(rule.id)}
                        onConfirm={() => {
                          setArmedDeleteRuleId(null);
                          onRemoveRule(rule.id);
                        }}
                        onCancel={() => setArmedDeleteRuleId(null)}
                      />
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
                  <th className="whitespace-nowrap px-3 py-3">
                    {t('rules.table.enabled.header')}
                  </th>
                  <th className="whitespace-nowrap px-3 py-3">
                    {t('rules.table.priority.header')}
                  </th>
                  <th className="min-w-[160px] whitespace-nowrap px-3 py-3">
                    {t('rules.table.name.header')}
                  </th>
                  <th className="px-3 py-3">
                    {t('rules.table.processes.header')}
                  </th>
                  <th className="px-3 py-3">{t('rules.table.targets.header')}</th>
                  <th className="whitespace-nowrap px-3 py-3">
                    {t('rules.table.ports.header')}
                  </th>
                  <th className="whitespace-nowrap px-3 py-3">
                    {t('rules.table.action.header')}
                  </th>
                  <th className="whitespace-nowrap px-3 py-3">
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
                    <td className="px-3 py-3">
                      <input name={`rule-enabled-${rule.id}`}
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={() => onToggleRule(rule.id)}
                        aria-label={`${t('rules.table.enabled.toggle_aria')}: ${rule.name}`}
                        className="h-4 w-4 cursor-pointer accent-tf-accent"
                      />
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 font-mono font-bold text-tf-accent">
                      #{rule.priority}
                    </td>
                    <td className="min-w-[160px] px-3 py-3 font-semibold text-tf-primary">
                      {rule.name}
                    </td>
                    <td className="px-3 py-3 font-mono text-[11px] text-tf-secondary">
                      {rule.processPatterns.length > 0
                        ? rule.processPatterns.join(', ')
                        : t('rules.table.processes.any')}
                    </td>
                    <td className="px-3 py-3 font-mono text-[11px] text-tf-secondary">
                      {[...rule.domainPatterns, ...rule.ipCidrs].length > 0
                        ? [...rule.domainPatterns, ...rule.ipCidrs].join(', ')
                        : t('rules.table.targets.any')}
                    </td>
                    <td className="px-3 py-3 font-mono text-[11px] text-tf-secondary">
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
                    <td className="whitespace-nowrap px-3 py-3">
                      <span
                        className={`inline-flex items-center whitespace-nowrap rounded px-2 py-0.5 font-mono text-[11px] font-bold ${
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
                    <td className="whitespace-nowrap px-3 py-3">
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
                          className="rounded p-1.5 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-accent"
                          title={t('rules.table.controls.edit')}
                          aria-label={`${t('rules.table.controls.edit')}: ${rule.name}`}
                        >
                          <Edit3 className="h-3.5 w-3.5" />
                        </button>
                        <ConfirmDeleteButton
                          armed={armedDeleteRuleId === rule.id}
                          title={t('rules.table.controls.delete')}
                          ariaLabel={`${t('rules.table.controls.delete')}: ${rule.name}`}
                          onArm={() => setArmedDeleteRuleId(rule.id)}
                          onConfirm={() => {
                            setArmedDeleteRuleId(null);
                            onRemoveRule(rule.id);
                          }}
                          onCancel={() => setArmedDeleteRuleId(null)}
                        />
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
                  <div className="flex items-center justify-between gap-2">
                    <label
                      htmlFor="simple-rule-target"
                      className="block text-xs text-tf-secondary"
                    >
                      {simpleTargetType === 'app'
                        ? t('rules.simple.target_app_label')
                        : t('rules.simple.target_site_label')}
                    </label>
                      {simpleTargetType === 'app' && (
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => appendProcessPattern('msedge.exe', 'simple')}
                            className="rounded border border-tf-cyan/40 bg-tf-cyan/10 px-2 py-0.5 text-[10px] font-semibold text-tf-cyan hover:bg-tf-cyan/20"
                          >
                            + {t('rules.simple.quick_edge_chip')}
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              void loadSystemApps();
                            }}
                            className="flex items-center gap-1 text-[11px] font-semibold text-tf-cyan hover:underline"
                          >
                            <FolderSearch className="h-3 w-3" />
                            {t('rules.modal.add.pick_app')}
                          </button>
                        </div>
                      )}
                  </div>
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
                  {simpleTargetType === 'site' &&
                    (() => {
                      const preview = normalizeDomainPatterns(simpleTargetValue);
                      return preview.normalizedFromUrl && preview.primaryDomain ? (
                        <p className="mt-1 text-[11px] font-semibold text-tf-green">
                          {t('rules.simple.url_preview', {
                            domain: preview.primaryDomain
                          })}
                        </p>
                      ) : null;
                    })()}
                  {simpleTargetType === 'app' && showAppPicker && (
                    <div className="mt-2 max-h-40 overflow-y-auto rounded-tf-md border border-tf-border bg-tf-surface-alt p-2 text-xs">
                      {loadingApps ? (
                        <div className="py-2 text-center text-tf-secondary">
                          {t('rules.modal.add.pick_app_loading')}
                        </div>
                      ) : systemApps.length === 0 ? (
                        <div className="py-2 text-center text-tf-secondary">
                          {t('rules.modal.add.pick_app_empty')}
                        </div>
                      ) : (
                        <div className="space-y-1">
                          {systemApps.map((app) => (
                            <button
                              key={`${app.name}-${app.executablePath}`}
                              type="button"
                              onClick={() => appendProcessPattern(app.name, 'simple')}
                              className="flex w-full items-center justify-between rounded px-2 py-1 text-left hover:bg-tf-surface"
                            >
                              <span className="truncate font-mono text-tf-primary">
                                {app.name}
                              </span>
                              <span
                                className={`ml-2 shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold ${
                                  app.running
                                    ? 'bg-tf-green/20 text-tf-green'
                                    : 'bg-tf-surface text-tf-secondary'
                                }`}
                              >
                                {app.running
                                  ? t('rules.modal.add.pick_app_running')
                                  : t('rules.modal.add.pick_app_installed')}
                              </span>
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                  {simpleTargetType === 'app' ? (
                    <div className="mt-3">
                      <label
                        htmlFor="simple-rule-optional-domains"
                        className="block text-xs text-tf-secondary"
                      >
                        {t('rules.simple.optional_site_label')}
                      </label>
                      <input
                        id="simple-rule-optional-domains"
                        type="text"
                        value={simpleOptionalDomains}
                        onChange={(e) => setSimpleOptionalDomains(e.target.value)}
                        placeholder={t('rules.simple.optional_site_placeholder')}
                        className="tf-input mt-1 w-full px-3 py-1.5 text-sm font-mono"
                      />
                      {(() => {
                        const preview = normalizeDomainPatterns(
                          simpleOptionalDomains
                        );
                        return preview.normalizedFromUrl && preview.primaryDomain ? (
                          <p className="mt-1 text-[11px] font-semibold text-tf-green">
                            {t('rules.simple.url_preview', {
                              domain: preview.primaryDomain
                            })}
                          </p>
                        ) : null;
                      })()}
                      <p className="mt-1 text-[11px] text-tf-secondary">
                        {t('rules.simple.optional_site_hint')}
                      </p>
                    </div>
                  ) : (
                    <div className="mt-3">
                      <div className="flex items-center justify-between gap-2">
                        <label
                          htmlFor="simple-rule-optional-apps"
                          className="block text-xs text-tf-secondary"
                        >
                          {t('rules.simple.optional_app_label')}
                        </label>
                        <button
                          type="button"
                          onClick={() =>
                            setSimpleOptionalApps((prev) =>
                              mergeCommaPattern(prev, 'msedge.exe')
                            )
                          }
                          className="rounded border border-tf-cyan/40 bg-tf-cyan/10 px-2 py-0.5 text-[10px] font-semibold text-tf-cyan hover:bg-tf-cyan/20"
                        >
                          + {t('rules.simple.quick_edge_chip')}
                        </button>
                      </div>
                      <input
                        id="simple-rule-optional-apps"
                        type="text"
                        value={simpleOptionalApps}
                        onChange={(e) => setSimpleOptionalApps(e.target.value)}
                        placeholder={t('rules.simple.optional_app_placeholder')}
                        className="tf-input mt-1 w-full px-3 py-1.5 text-sm font-mono"
                      />
                    </div>
                  )}
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
                          if (opt.type === 'proxy' && !hasEnabledProxy) {
                            onMissingProxy?.();
                            return;
                          }
                          setActionType(opt.type);
                          if (opt.type === 'proxy' && !actionTargetId) {
                            setActionTargetId(primaryEnabledProxyId);
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
                <label htmlFor={`${formId}-f1`} className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.name_label')}
                </label>
                <input id={`${formId}-f1`}
                  type="text"
                  required
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
              <div>
                <label htmlFor={`${formId}-f2`} className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.priority_label')}
                </label>
                <input id={`${formId}-f2`}
                  type="number"
                  required
                  value={priority}
                  onChange={(e) => setPriority(Number(e.target.value))}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between gap-2">
                <label
                  htmlFor={`${formId}-processes`}
                  className="block text-xs text-tf-secondary"
                >
                  {t('rules.modal.add.processes_label')}
                </label>
                <button
                  type="button"
                  onClick={() => {
                    void loadSystemApps();
                  }}
                  className="flex items-center gap-1 text-[11px] font-semibold text-tf-cyan hover:underline"
                >
                  <FolderSearch className="h-3 w-3" />
                  {t('rules.modal.add.pick_app')}
                </button>
              </div>
              <input
                id={`${formId}-processes`}
                type="text"
                value={processesText}
                onChange={(e) => setProcessesText(e.target.value)}
                className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
              />
              {showAppPicker && (
                <div className="mt-2 max-h-40 overflow-y-auto rounded-tf-md border border-tf-border bg-tf-surface-alt p-2 text-xs">
                  {loadingApps ? (
                    <div className="py-2 text-center text-tf-secondary">
                      {t('rules.modal.add.pick_app_loading')}
                    </div>
                  ) : systemApps.length === 0 ? (
                    <div className="py-2 text-center text-tf-secondary">
                      {t('rules.modal.add.pick_app_empty')}
                    </div>
                  ) : (
                    <div className="space-y-1">
                      {systemApps.map((app) => (
                        <button
                          key={`${app.name}-${app.executablePath}`}
                          type="button"
                          onClick={() => appendProcessPattern(app.name, 'advanced')}
                          className="flex w-full items-center justify-between rounded px-2 py-1 text-left hover:bg-tf-surface"
                        >
                          <span className="truncate font-mono text-tf-primary">
                            {app.name}
                          </span>
                          <span
                            className={`ml-2 shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold ${
                              app.running
                                ? 'bg-tf-green/20 text-tf-green'
                                : 'bg-tf-surface text-tf-secondary'
                            }`}
                          >
                            {app.running
                              ? t('rules.modal.add.pick_app_running')
                              : t('rules.modal.add.pick_app_installed')}
                          </span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label htmlFor={`${formId}-f3`} className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.domains_label')}
                </label>
                <input id={`${formId}-f3`}
                  type="text"
                  value={domainsText}
                  onChange={(e) => setDomainsText(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
              <div>
                <label htmlFor={`${formId}-f4`} className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.cidrs_label')}
                </label>
                <input id={`${formId}-f4`}
                  type="text"
                  value={cidrsText}
                  onChange={(e) => setCidrsText(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
            </div>
            <p className="text-[11px] text-tf-secondary">
              {t('rules.modal.add.negation_hint')}
            </p>

            <div className="grid grid-cols-3 gap-3">
              <div>
                <label htmlFor={`${formId}-f5`} className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.ports_label')}
                </label>
                <input id={`${formId}-f5`}
                  type="text"
                  value={portsText}
                  onChange={(e) => setPortsText(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
              <div>
                <label htmlFor={`${formId}-f6`} className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.protocol_label')}
                </label>
                <select id={`${formId}-f6`}
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
                <label htmlFor={`${formId}-f7`} className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.action_type_label')}
                </label>
                <select id={`${formId}-f7`}
                  value={actionType}
                  onChange={(e) => {
                    const nextType = e.target.value as RuleAction['type'];
                    setActionType(nextType);
                    if (nextType === 'proxy') {
                      setActionTargetId(primaryEnabledProxyId);
                    } else if (nextType === 'chain') {
                      setActionTargetId(enabledChains[0]?.id || '');
                    }
                  }}
                  className="tf-input mt-1 w-full px-2 py-1.5 text-sm uppercase"
                >
                  <option value="proxy" disabled={!hasEnabledProxy}>
                    PROXY
                  </option>
                  <option value="chain" disabled={enabledChains.length === 0}>
                    CHAIN
                  </option>
                  <option value="direct">DIRECT</option>
                  <option value="block">BLOCK</option>
                </select>
              </div>
            </div>

            {(actionType === 'proxy' || actionType === 'chain') && (
              <div>
                <label htmlFor={`${formId}-f8`} className="block text-xs text-tf-secondary">
                  {t('rules.modal.add.action_target_label')}
                </label>
                <select id={`${formId}-f8`}
                  value={actionTargetId}
                  onChange={(e) => setActionTargetId(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                >
                  {actionType === 'proxy'
                    ? enabledProxies.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name} ({p.host}:{p.port})
                        </option>
                      ))
                    : enabledChains.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name} (
                          {t('proxies.section.chains.hops', {
                            count: c.proxyIds.length
                          })}
                          )
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

      {/* Import FoxyProxy JSON Modal */}
      {showFoxyProxyModal && (
        <ModalContainer
          labelledBy={foxyModalTitleId}
          onClose={() => setShowFoxyProxyModal(false)}
          backdropClassName="bg-black/70 p-4"
        >
          <form
            onSubmit={(e) => {
              void handleSubmitFoxyProxy(e);
            }}
            className="tf-card w-full max-w-lg space-y-4 p-6"
          >
            <div className="flex items-start justify-between gap-2">
              <div>
                <h3
                  id={foxyModalTitleId}
                  className="text-base font-bold text-tf-primary"
                >
                  {t('rules.modal.foxyproxy.title')}
                </h3>
                <p className="mt-1 text-xs text-tf-secondary">
                  {t('rules.modal.foxyproxy.subtitle')}
                </p>
              </div>
              <input name="foxyproxy-file"
                ref={foxyFileInputRef}
                type="file"
                accept="application/json,.json"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) {
                    const reader = new FileReader();
                    reader.onload = () => {
                      if (typeof reader.result === 'string') {
                        setFoxyJsonText(reader.result);
                      }
                    };
                    reader.readAsText(file);
                  }
                  e.target.value = '';
                }}
              />
              <button
                type="button"
                onClick={() => foxyFileInputRef.current?.click()}
                className="tf-surface-alt flex shrink-0 items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-cyan hover:border-tf-cyan"
              >
                <Upload className="h-3.5 w-3.5" />
                {t('rules.modal.foxyproxy.load_file')}
              </button>
            </div>

            <div>
              <label
                htmlFor="foxyproxy-process-filter"
                className="block text-xs text-tf-secondary"
              >
                {t('rules.modal.foxyproxy.process_label')}
              </label>
              <input
                id="foxyproxy-process-filter"
                type="text"
                value={foxyProcessFilter}
                onChange={(e) => setFoxyProcessFilter(e.target.value)}
                placeholder={t('rules.modal.foxyproxy.process_placeholder')}
                className="tf-input mt-1 w-full px-3 py-1.5 text-sm font-mono"
              />
            </div>

            <textarea name="foxyproxy-json"
              rows={6}
              required
              aria-label={t('rules.modal.foxyproxy.title')}
              value={foxyJsonText}
              onChange={(e) => setFoxyJsonText(e.target.value)}
              placeholder={t('rules.modal.foxyproxy.json_placeholder')}
              className="tf-input w-full p-3 font-mono text-xs"
            />

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowFoxyProxyModal(false)}
                className="tf-surface-alt px-4 py-1.5 text-xs text-tf-secondary"
              >
                {t('rules.modal.foxyproxy.cancel')}
              </button>
              <button
                type="submit"
                disabled={foxySubmitting}
                className="tf-btn-accent px-4 py-1.5 text-xs disabled:opacity-60"
              >
                {t('rules.modal.foxyproxy.submit')}
              </button>
            </div>
          </form>
        </ModalContainer>
      )}
    </div>
  );
};
