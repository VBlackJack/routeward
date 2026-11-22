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

import { SYSTEM_CONSTANTS } from '../config/constants';
import {
  PortRange,
  ProxyChain,
  ProxyNode,
  RoutingRule,
  SecurityPolicyConfig,
  TransportProtocol
} from '../types/routeward';
import { resolveSimpleProxyAction, Translate } from './friendly';

export type UseCaseId = 'privacy' | 'work' | 'gaming' | 'strict';

/** The five anti-leak switches that the all-in-one shield and the use-case cards touch. */
export const SHIELD_SETTING_KEYS = [
  'killSwitchEnabled',
  'blockUdpOnTcpOnlyProxy',
  'strictDnsNoLocalFallback',
  'blockQuicUdp443',
  'blockEncryptedDnsBypass'
] as const;

export type ShieldSettingKey = (typeof SHIELD_SETTING_KEYS)[number];
export type ShieldMix = Record<ShieldSettingKey, boolean>;

/** Plain-language label of each switch, shown in the confirmation dialog. */
export const SHIELD_SETTING_LABEL_KEYS: Record<ShieldSettingKey, string> = {
  killSwitchEnabled: 'dashboard.confirm.setting.kill_switch',
  blockUdpOnTcpOnlyProxy: 'dashboard.confirm.setting.udp_guard',
  strictDnsNoLocalFallback: 'dashboard.confirm.setting.dns_guard',
  blockQuicUdp443: 'dashboard.confirm.setting.quic_guard',
  blockEncryptedDnsBypass: 'dashboard.confirm.setting.encrypted_dns_guard'
};

/** Switches that are on when the saved policy does not mention them. */
const SHIELD_DEFAULT_ON = true;

interface UseCaseDefinition {
  security: Partial<ShieldMix>;
  presetIds: readonly string[];
  visualAppIds: readonly string[];
}

const USE_CASES: Record<UseCaseId, UseCaseDefinition> = {
  privacy: {
    security: { killSwitchEnabled: true, strictDnsNoLocalFallback: true },
    presetIds: [
      'preset-privacy-browsers',
      'preset-block-os-telemetry',
      'preset-rfc1918-direct'
    ],
    visualAppIds: []
  },
  work: {
    security: { strictDnsNoLocalFallback: true },
    presetIds: ['preset-dev-toolchains', 'preset-rfc1918-direct'],
    visualAppIds: []
  },
  gaming: {
    security: {},
    presetIds: ['preset-privacy-browsers'],
    visualAppIds: ['app-gaming']
  },
  strict: {
    security: {
      killSwitchEnabled: true,
      blockUdpOnTcpOnlyProxy: true,
      strictDnsNoLocalFallback: true,
      blockQuicUdp443: true,
      blockEncryptedDnsBypass: true
    },
    presetIds: ['preset-block-os-telemetry'],
    visualAppIds: []
  }
};

const USE_CASE_PRESET_RULE_PREFIX = 'rule-uc-';
const VISUAL_APP_RULE_PREFIX = 'rule-visual-';

/** Reads the five switches of a policy, counting a missing one as on (like the engine does). */
export function readShieldMix(policy: SecurityPolicyConfig): ShieldMix {
  return {
    killSwitchEnabled: policy.killSwitchEnabled,
    blockUdpOnTcpOnlyProxy: policy.blockUdpOnTcpOnlyProxy,
    strictDnsNoLocalFallback: policy.strictDnsNoLocalFallback,
    blockQuicUdp443: policy.blockQuicUdp443 ?? SHIELD_DEFAULT_ON,
    blockEncryptedDnsBypass: policy.blockEncryptedDnsBypass ?? SHIELD_DEFAULT_ON
  };
}

export function isShieldFullyOn(policy: SecurityPolicyConfig): boolean {
  const mix = readShieldMix(policy);
  return SHIELD_SETTING_KEYS.every((key) => mix[key]);
}

function allShieldSettings(value: boolean): ShieldMix {
  return {
    killSwitchEnabled: value,
    blockUdpOnTcpOnlyProxy: value,
    strictDnsNoLocalFallback: value,
    blockQuicUdp443: value,
    blockEncryptedDnsBypass: value
  };
}

export interface ShieldTogglePlan {
  /** Settings to send to the daemon. */
  apply: ShieldMix;
  /** The mix to put back on "undo". */
  undo: ShieldMix;
  /** The user's own mix to remember when the shield is turned on, null when nothing to remember. */
  remember: ShieldMix | null;
}

/**
 * Plans the all-in-one shield. Turning it on remembers the current mix; turning it off puts
 * that mix back (all off when none was remembered, or when the remembered mix is itself full).
 */
export function planShieldToggle(
  policy: SecurityPolicyConfig,
  next: boolean,
  rememberedMix: ShieldMix | null
): ShieldTogglePlan {
  const current = readShieldMix(policy);
  if (next) {
    return {
      apply: allShieldSettings(true),
      undo: current,
      remember: current
    };
  }
  const restored =
    rememberedMix && !SHIELD_SETTING_KEYS.every((key) => rememberedMix[key])
      ? rememberedMix
      : allShieldSettings(false);
  return { apply: restored, undo: current, remember: null };
}

/** The settings among `wanted` whose current value differs, with the value they have now. */
export function diffSecurityChanges(
  policy: SecurityPolicyConfig,
  wanted: Partial<ShieldMix>
): { changed: ShieldSettingKey[]; previous: Partial<ShieldMix> } {
  const current = readShieldMix(policy);
  const changed: ShieldSettingKey[] = [];
  const previous: Partial<ShieldMix> = {};
  for (const key of SHIELD_SETTING_KEYS) {
    const target = wanted[key];
    if (target !== undefined && target !== current[key]) {
      changed.push(key);
      previous[key] = current[key];
    }
  }
  return { changed, previous };
}

export interface UseCasePlan {
  /** Security settings the card wants on. */
  security: Partial<ShieldMix>;
  /** Rules the card creates, ready to send. */
  rules: RoutingRule[];
  /** True when a rule was left out because it needs a proxy and none is set up. */
  skippedProxyRule: boolean;
}

interface BuildContext {
  t: Translate;
  proxies: ProxyNode[];
  chains: ProxyChain[];
}

function findPreset(presetId: string) {
  return SYSTEM_CONSTANTS.rulePresets.find((p) => p.id === presetId);
}

/** Builds the rules of one use-case card, without sending anything. */
export function planUseCase(useCase: UseCaseId, ctx: BuildContext): UseCasePlan {
  const definition = USE_CASES[useCase];
  const enabledProxies = ctx.proxies.filter((p) => p.enabled);
  const primaryProxyId = enabledProxies[0]?.id;
  const enabledChains = primaryProxyId
    ? ctx.chains.filter(
        (c) =>
          c.enabled &&
          c.proxyIds.some((pid) => enabledProxies.some((p) => p.id === pid))
      )
    : [];
  const simpleProxyAction = resolveSimpleProxyAction(ctx.proxies, ctx.chains);
  const rules: RoutingRule[] = [];
  let skippedProxyRule = false;

  for (const appId of definition.visualAppIds) {
    const app = SYSTEM_CONSTANTS.visualAppCatalog.find((c) => c.id === appId);
    if (!app) continue;
    rules.push({
      id: `${VISUAL_APP_RULE_PREFIX}${app.id}`,
      name: ctx.t(`${app.i18nKey}.name`),
      enabled: true,
      priority: app.priority,
      processPatterns: [...app.processPatterns],
      domainPatterns: [],
      ipCidrs: [],
      portRanges: [],
      protocol: 'any',
      action: { type: 'direct' }
    });
  }

  for (const presetId of definition.presetIds) {
    const preset = findPreset(presetId);
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
      skippedProxyRule = true;
      continue;
    }
    rules.push({
      id: `${USE_CASE_PRESET_RULE_PREFIX}${preset.id}`,
      name: ctx.t(`${preset.i18nKey}.name`),
      enabled: true,
      priority: preset.priority,
      processPatterns: [...preset.processPatterns],
      domainPatterns: [...preset.domainPatterns],
      ipCidrs: [...preset.ipCidrs],
      portRanges: [...preset.portRanges] as PortRange[],
      protocol: preset.protocol as TransportProtocol,
      action: targetId ? { type: actType, targetId } : { type: actType }
    });
  }

  return { security: definition.security, rules, skippedProxyRule };
}

/**
 * True when the profile really holds what the card sets up: every switch is on and every rule it
 * creates exists and is enabled. The badge never relies on "I clicked it once".
 */
export function isUseCaseApplied(
  useCase: UseCaseId,
  policy: SecurityPolicyConfig,
  rules: RoutingRule[],
  proxies: ProxyNode[],
  chains: ProxyChain[]
): boolean {
  const plan = planUseCase(useCase, { t: (key) => key, proxies, chains });
  const mix = readShieldMix(policy);
  const securityOk = SHIELD_SETTING_KEYS.every(
    (key) => plan.security[key] === undefined || mix[key] === plan.security[key]
  );
  if (!securityOk) {
    return false;
  }
  return plan.rules.every((planned) =>
    rules.some((existing) => existing.id === planned.id && existing.enabled)
  );
}
