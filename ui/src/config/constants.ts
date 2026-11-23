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
    NETWORK_PROFILE_RULES: 'routeward_network_profiles',
    SERVICE_NOTICE_SHOWN: 'routeward_service_notice_shown'
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
  /** Default port suggested for each proxy protocol when the user has not typed one. */
  DEFAULT_PROXY_PORT_BY_PROTOCOL: {
    socks5: 1080,
    socks4: 1080,
    http: 8080,
    https: 8080
  } as const,
  /** Protocol assumed for a proxy link typed without a scheme when the user picked none. */
  DEFAULT_LINK_PROXY_PROTOCOL: 'http' as const,
  DEFAULT_RULE_PRIORITY: 50,
  /** Priority of Simple rules that target one website (above every category rule and pack but the LAN bypass). */
  DEFAULT_SITE_RULE_PRIORITY: 8,
  /**
   * Priority of Simple rules that target one application: above the category cards (16-22),
   * below the protection packs (5-14) so the local network bypass and ad blocking keep working.
   */
  SIMPLE_APP_RULE_PRIORITY: 15,
  /** Prefixes of the rule ids created from Simple entry points (the only rules Simple actions may retarget). */
  SIMPLE_RULE_ID_PREFIXES: {
    APP: 'rule-app-',
    SITE: 'rule-site-',
    VISUAL: 'rule-visual-',
    WIZARD: 'rule-wiz-',
    QUICK: 'rule-quick-',
    USE_CASE: 'rule-uc-'
  } as const,
  /** Name the engine gives the implicit fallback rule; shown through a localized label. */
  ENGINE_DEFAULT_RULE_NAME: 'Default Profile Policy',
  /** Process used by the Simple site tester to evaluate a website. */
  SITE_TESTER_PROCESS: 'msedge.exe',
  /** Value of the OS name reported by the daemon on Windows. */
  WINDOWS_OS_NAME: 'WINDOWS',
  WINDOWS_USER_AGENT_PATTERN: /windows/i,
  WINDOWS_EXECUTABLE_SUFFIX: '.exe',
  /** Longest list of targets printed on one Simple rule row before it is summarized. */
  SIMPLE_RULE_TARGETS_PREVIEW: 4,
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
  /** Maximum rows rendered at once in live Connections and Logs tables before windowing. */
  MAX_RENDERED_TABLE_ROWS: 250,
  /** Auto-dismiss delay for non-error toasts; error toasts stay until dismissed. */
  TOAST_DURATION_MS: 3200,
  /** Extended auto-dismiss delay for toasts that carry an Undo action. */
  TOAST_UNDO_DURATION_MS: 6000,
  /** Seconds in one minute, used to turn a pause length in minutes into the daemon's seconds. */
  SECONDS_PER_MINUTE: 60,
  /** Pause length (minutes) offered by the outage banner and the troubleshooter. */
  OUTAGE_PAUSE_MINUTES: 15,
  /** A pause that ended up to this long before now (ms) counts as having run its course. */
  PAUSE_RESUME_TOAST_TOLERANCE_MS: 5000,
  /** Delay between two refreshes of the pause countdown (milliseconds). */
  PAUSE_COUNTDOWN_TICK_MS: 1000,
  /** Quick temporary pause durations (in minutes) shown in Simple mode. */
  TEMPORARY_PAUSE_OPTIONS_MINUTES: [15, 60] as const,
  /** Stable identifier of the automatic backup-proxy failover chain managed in Simple mode. */
  SIMPLE_FAILOVER_CHAIN_ID: 'chain-simple-failover',
  /** Priority for high-priority quick unblock rules created from troubleshooting. */
  TROUBLESHOOT_RULE_PRIORITY: 6,
  /** Length of the "15 minutes" temporary unblock (milliseconds). */
  UNBLOCK_SHORT_DURATION_MS: 15 * 60 * 1000,
  /** Length of the "1 hour" temporary unblock (milliseconds). */
  UNBLOCK_LONG_DURATION_MS: 60 * 60 * 1000,
  /** Prefixes of the exception rules created by the Unblock flow. */
  UNBLOCK_RULE_ID_PREFIXES: {
    APP: 'rule-unblock-app-',
    SITE: 'rule-unblock-site-'
  } as const,
  /** Suffixes appended to an exception id so variants never replace each other. */
  UNBLOCK_RULE_ID_SUFFIXES: {
    PROXY: '-proxy',
    TEMPORARY: '-tmp'
  } as const,
  /** Refresh period of the Blocked tab while it is open (milliseconds). */
  BLOCKED_REFRESH_INTERVAL_MS: 3000,
  /** How often the remaining time of a temporary rule is refreshed (milliseconds). */
  TEMPORARY_RULE_TICK_MS: 30_000,
  /** Half-width of the time window opened by "See logs" from a connection (milliseconds). */
  LOG_JUMP_WINDOW_MS: 30000,
  /** Number of log lines requested per page from the daemon. */
  LOG_QUERY_PAGE_SIZE: 200,
  /** Time ranges offered by the logs filter (milliseconds, 0 means no limit). */
  LOG_TIME_RANGE_MS: {
    ALL: 0,
    LAST_15_MIN: 15 * 60 * 1000,
    LAST_HOUR: 60 * 60 * 1000,
    LAST_DAY: 24 * 60 * 60 * 1000
  } as const,
  /** Days of daemon log files offered for the diagnostic export, and the default. */
  DIAGNOSTIC_LOG_DAYS_OPTIONS: [1, 3, 7, 14] as const,
  DIAGNOSTIC_LOG_DAYS_DEFAULT: 3,
  /** Prefix of the diagnostic file name (a date and the extension follow). */
  DIAGNOSTIC_FILE_PREFIX: 'routeward-diagnostic-',
  /**
   * 1-click protection and compatibility packs offered in Simple mode (works even without a proxy).
   * Each pack owns one or more rules; the engine ANDs processes and domains inside one rule, so a
   * pack that targets both programs and websites is split into one rule per criterion.
   */
  SIMPLE_PROTECTION_PACKS: [
    {
      id: 'rule-pack-local-lan',
      titleKey: 'rules.simple.pack_lan_title',
      descKey: 'rules.simple.pack_lan_desc',
      actionType: 'direct' as const,
      priority: 5,
      rules: [
        {
          id: 'rule-pack-local-lan',
          nameKey: 'rules.simple.pack_lan_title',
          processPatterns: [] as readonly string[],
          domainPatterns: ['localhost', '*.local', '*.lan'] as readonly string[],
          ipCidrs: [
            '127.0.0.0/8',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '169.254.0.0/16'
          ] as readonly string[]
        }
      ]
    },
    {
      id: 'rule-pack-ads-trackers',
      titleKey: 'rules.simple.pack_ads_title',
      descKey: 'rules.simple.pack_ads_desc',
      actionType: 'block' as const,
      priority: 13,
      rules: [
        {
          id: 'rule-pack-ads-trackers',
          nameKey: 'rules.simple.pack_ads_title',
          processPatterns: [] as readonly string[],
          domainPatterns: [
            '*.doubleclick.net',
            '*.googlesyndication.com',
            '*.google-analytics.com',
            '*.adservice.google.com',
            '*.adsrvr.org',
            '*.taboola.com',
            '*.outbrain.com'
          ] as readonly string[],
          ipCidrs: [] as readonly string[]
        }
      ]
    },
    {
      id: 'rule-pack-telemetry',
      titleKey: 'rules.simple.pack_telemetry_title',
      descKey: 'rules.simple.pack_telemetry_desc',
      actionType: 'block' as const,
      priority: 12,
      rules: [
        {
          id: 'rule-pack-telemetry',
          nameKey: 'rules.simple.pack_telemetry_apps_name',
          processPatterns: [
            'CompatTelRunner.exe',
            'crashpad_handler.exe'
          ] as readonly string[],
          domainPatterns: [] as readonly string[],
          ipCidrs: [] as readonly string[]
        },
        {
          id: 'rule-pack-telemetry-sites',
          nameKey: 'rules.simple.pack_telemetry_sites_name',
          processPatterns: [] as readonly string[],
          domainPatterns: [
            '*.telemetry.*',
            '*.events.data.microsoft.com',
            '*.sentry.io'
          ] as readonly string[],
          ipCidrs: [] as readonly string[]
        }
      ]
    },
    {
      id: 'rule-pack-social-focus',
      titleKey: 'rules.simple.pack_social_title',
      descKey: 'rules.simple.pack_social_desc',
      actionType: 'block' as const,
      priority: 14,
      rules: [
        {
          id: 'rule-pack-social-focus',
          nameKey: 'rules.simple.pack_social_title',
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
          ] as readonly string[],
          ipCidrs: [] as readonly string[]
        }
      ]
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
    ENGINE_PAUSE: '/api/engine/pause',
    ENGINE_MODE: '/api/engine/mode',
    PROFILE_REPLACE: '/api/profile/replace',
    THEME: '/api/theme',
    RULES_UPSERT: '/api/rules/upsert',
    RULES_REMOVE: '/api/rules/remove',
    RULES_EVALUATE: '/api/rules/evaluate',
    PROXIES_UPSERT: '/api/proxies/upsert',
    PROXIES_REMOVE: '/api/proxies/remove',
    PROXIES_SET_PRIMARY: '/api/proxies/set-primary',
    PROXIES_TEST: '/api/proxies/test',
    PROXIES_TEST_ALL: '/api/proxies/test-all',
    CHAINS_UPSERT: '/api/chains/upsert',
    CHAINS_REMOVE: '/api/chains/remove',
    CONNECTIONS_TERMINATE: '/api/connections/terminate',
    CONNECTIONS_CLEAR: '/api/connections/clear',
    SCAN_OS: '/api/scan-os',
    DNS_ALLOCATE: '/api/dns/allocate',
    DNS_FLUSH: '/api/dns/flush',
    SYSTEM_FLUSH_OS_DNS: '/api/system/flush-os-dns',
    LOGS_CLEAR: '/api/logs/clear',
    LOGS_QUERY: '/api/logs/query',
    BLOCKED: '/api/blocked',
    DIAGNOSTICS_ANALYZE: '/api/diagnostics/analyze',
    DIAGNOSTICS_COLLECT: '/api/diagnostics/collect',
    RULES_PREVIEW: '/api/rules/preview',
    SYSTEM_PROXY: '/api/system-proxy',
    SYSTEM_PAC: '/api/system/pac',
    SYSTEM_AUTOSTART: '/api/system/autostart',
    SYSTEM_APPS: '/api/system/apps',
    SYSTEM_DETECT_PROXIES: '/api/system/detect-proxies',
    SYSTEM_NETWORK_INFO: '/api/system/network-info',
    SYSTEM_DIRECT_IP: '/api/system/direct-ip',
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
