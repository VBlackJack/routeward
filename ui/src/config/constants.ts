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

import systemConstantsJson from '../../../configs/system_constants.json';
import defaultProfileJson from '../../../configs/default_profile.json';
import themeForgeCatalogJson from '../../../configs/themeforge_palettes.json';

export const SYSTEM_CONSTANTS = systemConstantsJson;
export const DEFAULT_PROFILE_DATA = defaultProfileJson;
export const THEMEFORGE_CATALOG_DATA = themeForgeCatalogJson;

const IP_CHECK_URL = 'https://api.ipify.org?format=json';

export const UI_CONFIG = {
  DEFAULT_LOCALE: 'fr',
  SUPPORTED_LOCALES: ['fr', 'en'] as const,
  STORAGE_KEYS: {
    THEME: 'routeward_tf_theme',
    ACCENT: 'routeward_tf_accent',
    CUSTOM_PALETTES: 'routeward_tf_custom_palettes',
    LOCALE: 'routeward_locale',
    PROFILE: 'routeward_active_profile',
    EXPERIENCE_MODE: 'routeward_ux_mode',
    WIZARD_COMPLETED: 'routeward_wizard_done',
    NETWORK_PROFILE_RULES: 'routeward_network_profiles'
  },
  NETWORK_POLL_INTERVAL_MS: 15000,
  TELEMETRY_REFRESH_INTERVAL_MS: 1000,
  /** Locale keys of the byte unit labels, from bytes up to gigabytes. */
  BYTE_UNIT_KEYS: [
    'format.bytes.b',
    'format.bytes.kb',
    'format.bytes.mb',
    'format.bytes.gb'
  ] as const,
  BYTE_STEP: 1024,
  HIGH_CONTRAST_BORDER_PX: '2px',
  STANDARD_BORDER_PX: '1px',
  ACCENT_HOVER_LIGHTNESS_DELTA: 18,
  ACCENT_PRESSED_LIGHTNESS_DELTA: -18,
  DEFAULT_PROXY_PORT: 1080,
  DEFAULT_RULE_PRIORITY: 50,
  DEFAULT_TEST_PORT: 443,
  TOKEN_HEADER: 'X-RouteWard-Token',
  SSE_RECONNECT_DELAY_MS: 1500,
  /** Interval of the background state refresh that picks up engine changes made outside the UI (CLI, tray). */
  STATE_REFRESH_INTERVAL_MS: 3000,
  /** Timeout of one background state poll, shorter than ordinary requests so a slow daemon never stacks polls. */
  STATE_POLL_TIMEOUT_MS: 2000,
  /** Minimum delay between two UI renders triggered by a burst of SSE events. */
  STREAM_NOTIFY_COALESCE_MS: 100,
  /** Timeout applied to ordinary bridge requests. */
  REQUEST_TIMEOUT_MS: 30000,
  /** Timeout for slow bridge operations (health checks, socket scan, daemon launch). */
  LONG_REQUEST_TIMEOUT_MS: 120000,
  /** Auto-dismiss delay for non-error toasts; error toasts stay until dismissed. */
  TOAST_DURATION_MS: 3200,
  /** Quick temporary pause durations (in minutes) shown in Simple mode. */
  TEMPORARY_PAUSE_OPTIONS_MINUTES: [15, 60] as const,
  /** Stable identifier of the automatic backup-proxy failover chain managed in Simple mode. */
  SIMPLE_FAILOVER_CHAIN_ID: 'chain-simple-failover',
  /** Priority for high-priority quick unblock rules created from troubleshooting. */
  TROUBLESHOOT_RULE_PRIORITY: 6,
  /** 1-click protection packs offered in Simple mode (works even without a proxy). */
  SIMPLE_PROTECTION_PACKS: [
    {
      id: 'rule-pack-ads-trackers',
      titleKey: 'rules.simple.pack_ads_title',
      descKey: 'rules.simple.pack_ads_desc',
      priority: 13,
      processPatterns: [] as readonly string[],
      domainPatterns: [
        '*.doubleclick.net',
        '*.googlesyndication.com',
        '*.google-analytics.com',
        '*.adservice.google.com',
        '*.adsrvr.org',
        '*.taboola.com',
        '*.outbrain.com'
      ] as readonly string[]
    },
    {
      id: 'rule-pack-telemetry',
      titleKey: 'rules.simple.pack_telemetry_title',
      descKey: 'rules.simple.pack_telemetry_desc',
      priority: 12,
      processPatterns: [
        'CompatTelRunner.exe',
        'DiagTrack',
        'crashpad_handler.exe'
      ] as readonly string[],
      domainPatterns: [
        '*.telemetry.*',
        '*.events.data.microsoft.com',
        '*.sentry.io'
      ] as readonly string[]
    },
    {
      id: 'rule-pack-social-focus',
      titleKey: 'rules.simple.pack_social_title',
      descKey: 'rules.simple.pack_social_desc',
      priority: 14,
      processPatterns: [] as readonly string[],
      domainPatterns: [
        'tiktok.com',
        '*.tiktok.com',
        'instagram.com',
        '*.instagram.com',
        'x.com',
        '*.x.com',
        'facebook.com',
        '*.facebook.com',
        'reddit.com',
        '*.reddit.com'
      ] as readonly string[]
    }
  ] as const,
  /** Priority gap used when reordering rules. */
  PRIORITY_STEP: 5,
  /** Connection cache bound used when system constants do not provide one. */
  CONNECTION_CACHE_FALLBACK_ENTRIES: 500,
  MAX_PORT: 65535,
  PAC_PATH: '/proxy.pac',
  /** Quick-launch presets of the process launcher modal. */
  IP_CHECK_URL,
  QUICK_LAUNCH_PRESETS: [
    { exe: 'curl.exe', args: [IP_CHECK_URL] },
    { exe: 'powershell.exe', args: ['-NoExit'] },
    { exe: 'cmd.exe', args: [] }
  ] as ReadonlyArray<{ exe: string; args: readonly string[] }>,
  API_ENDPOINTS: {
    STATE: '/api/state',
    EVENTS: '/api/events',
    ENGINE_TOGGLE: '/api/engine/toggle',
    ENGINE_MODE: '/api/engine/mode',
    PROFILE_REPLACE: '/api/profile/replace',
    THEME: '/api/theme',
    RULES_UPSERT: '/api/rules/upsert',
    RULES_REMOVE: '/api/rules/remove',
    RULES_EVALUATE: '/api/rules/evaluate',
    PROXIES_UPSERT: '/api/proxies/upsert',
    PROXIES_REMOVE: '/api/proxies/remove',
    PROXIES_TEST: '/api/proxies/test',
    PROXIES_TEST_ALL: '/api/proxies/test-all',
    CHAINS_UPSERT: '/api/chains/upsert',
    CHAINS_REMOVE: '/api/chains/remove',
    CONNECTIONS_TERMINATE: '/api/connections/terminate',
    CONNECTIONS_CLEAR: '/api/connections/clear',
    SCAN_OS: '/api/scan-os',
    DNS_ALLOCATE: '/api/dns/allocate',
    DNS_FLUSH: '/api/dns/flush',
    LOGS_CLEAR: '/api/logs/clear',
    SYSTEM_PROXY: '/api/system-proxy',
    SYSTEM_PAC: '/api/system/pac',
    SYSTEM_AUTOSTART: '/api/system/autostart',
    SYSTEM_APPS: '/api/system/apps',
    SYSTEM_DETECT_PROXIES: '/api/system/detect-proxies',
    SYSTEM_NETWORK_INFO: '/api/system/network-info',
    IMPORT_FOXYPROXY: '/api/import/foxyproxy',
    PROFILES_LIST: '/api/profiles',
    PROFILES_SAVE: '/api/profiles/save',
    PROFILES_SWITCH: '/api/profiles/switch',
    PROFILES_DELETE: '/api/profiles/delete',
    LAUNCH_PROCESS: '/api/launch-process',
    DAEMON_START: '/api/daemon/start',
    LOCALE: '/api/locale'
  }
} as const;

/** Default PAC URL served by the desktop bridge, built from the shipped system constants. */
export function buildDefaultPacUrl(): string {
  const net = SYSTEM_CONSTANTS.network;
  return `http://${net.localBindHost}:${net.defaultPacPort}${UI_CONFIG.PAC_PATH}`;
}
