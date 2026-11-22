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

import { ProxyNode, SystemDiagnostics } from '../types/routeward';

/** What the last test of the primary proxy said. `unknown` means it was never tested. */
export type ProxyReachability = 'reachable' | 'unreachable' | 'unknown';

/**
 * The single answer to "am I protected?" shared by the header pill, the home hero, the
 * checklist and the expert banner.
 */
export type ProtectionHealthState =
  | 'service_stopped'
  | 'stopped'
  | 'paused'
  | 'error'
  | 'active_proxy_ok'
  | 'active_proxy_untested'
  | 'active_proxy_unreachable'
  | 'active_no_proxy';

export type ProtectionHealthTone = 'ok' | 'warn' | 'bad';

export interface ProtectionHealth {
  state: ProtectionHealthState;
  tone: ProtectionHealthTone;
  /** Unix time (ms) at which a pause ends, only set in the `paused` state. */
  pausedUntilEpochMs: number | null;
  /** True when the engine is filtering traffic (any `active_*` state). */
  engineActive: boolean;
  /** True only when a proxy answered its last test: the one state that may claim a hidden IP. */
  ipHidden: boolean;
  /** Error key reported by the daemon for the `error` state. */
  errorKey: string | null;
}

export interface ProtectionHealthInput {
  diagnostics: Pick<
    SystemDiagnostics,
    'daemonConnected' | 'running' | 'pausedUntilEpochMs' | 'autoStartErrorKey'
  >;
  primaryProxy: ProxyNode | null;
  proxyReachability: ProxyReachability;
}

/** Locale keys of one health state, kept as literals so every key stays traceable in sources. */
export interface ProtectionHealthTexts {
  pill: string;
  title: string;
  desc: string;
  badge: string;
}

export const PROTECTION_HEALTH_TEXTS: Record<
  ProtectionHealthState,
  ProtectionHealthTexts
> = {
  service_stopped: {
    pill: 'dashboard.health.service_stopped.pill',
    title: 'dashboard.health.service_stopped.title',
    desc: 'dashboard.health.service_stopped.desc',
    badge: 'dashboard.health.service_stopped.badge'
  },
  stopped: {
    pill: 'dashboard.health.stopped.pill',
    title: 'dashboard.health.stopped.title',
    desc: 'dashboard.health.stopped.desc',
    badge: 'dashboard.health.stopped.badge'
  },
  paused: {
    pill: 'dashboard.health.paused.pill',
    title: 'dashboard.health.paused.title',
    desc: 'dashboard.health.paused.desc',
    badge: 'dashboard.health.paused.badge'
  },
  error: {
    pill: 'dashboard.health.error.pill',
    title: 'dashboard.health.error.title',
    desc: 'dashboard.health.error.desc',
    badge: 'dashboard.health.error.badge'
  },
  active_proxy_ok: {
    pill: 'dashboard.health.active_proxy_ok.pill',
    title: 'dashboard.health.active_proxy_ok.title',
    desc: 'dashboard.health.active_proxy_ok.desc',
    badge: 'dashboard.health.active_proxy_ok.badge'
  },
  active_proxy_untested: {
    pill: 'dashboard.health.active_proxy_untested.pill',
    title: 'dashboard.health.active_proxy_untested.title',
    desc: 'dashboard.health.active_proxy_untested.desc',
    badge: 'dashboard.health.active_proxy_untested.badge'
  },
  active_proxy_unreachable: {
    pill: 'dashboard.health.active_proxy_unreachable.pill',
    title: 'dashboard.health.active_proxy_unreachable.title',
    desc: 'dashboard.health.active_proxy_unreachable.desc',
    badge: 'dashboard.health.active_proxy_unreachable.badge'
  },
  active_no_proxy: {
    pill: 'dashboard.health.active_no_proxy.pill',
    title: 'dashboard.health.active_no_proxy.title',
    desc: 'dashboard.health.active_no_proxy.desc',
    badge: 'dashboard.health.active_no_proxy.badge'
  }
};

/**
 * Combines the engine state, the pause deadline and the last proxy test into one state.
 * "Your IP is hidden" is only ever the answer when a proxy answered its test.
 */
export function computeProtectionHealth(
  input: ProtectionHealthInput
): ProtectionHealth {
  const { diagnostics, primaryProxy, proxyReachability } = input;
  const base: ProtectionHealth = {
    state: 'stopped',
    tone: 'bad',
    pausedUntilEpochMs: null,
    engineActive: false,
    ipHidden: false,
    errorKey: null
  };

  if (!diagnostics.daemonConnected) {
    return { ...base, state: 'service_stopped' };
  }

  if (!diagnostics.running) {
    if (diagnostics.pausedUntilEpochMs !== null) {
      return {
        ...base,
        state: 'paused',
        tone: 'warn',
        pausedUntilEpochMs: diagnostics.pausedUntilEpochMs
      };
    }
    if (diagnostics.autoStartErrorKey) {
      return {
        ...base,
        state: 'error',
        errorKey: diagnostics.autoStartErrorKey
      };
    }
    return base;
  }

  const active = { ...base, engineActive: true };
  if (!primaryProxy) {
    return { ...active, state: 'active_no_proxy', tone: 'warn' };
  }
  if (proxyReachability === 'unreachable') {
    return { ...active, state: 'active_proxy_unreachable', tone: 'bad' };
  }
  if (proxyReachability === 'reachable') {
    return { ...active, state: 'active_proxy_ok', tone: 'ok', ipHidden: true };
  }
  return { ...active, state: 'active_proxy_untested', tone: 'warn' };
}

/**
 * Reads the reachability of a proxy from the tests the UI recorded, falling back to the
 * latency the daemon stored after a successful test.
 */
export function resolveProxyReachability(
  proxy: ProxyNode | null,
  unreachableProxyIds: readonly string[],
  reachableProxyIds: readonly string[],
  outageDetected: boolean
): ProxyReachability {
  if (!proxy) {
    return 'unknown';
  }
  if (outageDetected || unreachableProxyIds.includes(proxy.id)) {
    return 'unreachable';
  }
  if (reachableProxyIds.includes(proxy.id) || proxy.lastLatencyMs !== null) {
    return 'reachable';
  }
  return 'unknown';
}

/** Formats the end of a pause as a local wall-clock time (for example 14:35). */
export function formatPauseEnd(epochMs: number, locale: string): string {
  return new Intl.DateTimeFormat(locale, {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  }).format(new Date(epochMs));
}

const MS_PER_SECOND = 1000;

/** Whole seconds left until `epochMs`, never negative. */
export function secondsUntil(epochMs: number, nowMs: number): number {
  return Math.max(0, Math.ceil((epochMs - nowMs) / MS_PER_SECOND));
}
