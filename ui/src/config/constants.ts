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
    WIZARD_COMPLETED: 'routeward_wizard_done'
  },
  TELEMETRY_REFRESH_INTERVAL_MS: 1000,
  BYTE_UNITS: ['B', 'KB', 'MB', 'GB'] as const,
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
    LAUNCH_PROCESS: '/api/launch-process',
    DAEMON_START: '/api/daemon/start',
    LOCALE: '/api/locale'
  }
} as const;
