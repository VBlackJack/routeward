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
    THEME: 'proxifier_tf_theme',
    ACCENT: 'proxifier_tf_accent',
    CUSTOM_PALETTES: 'proxifier_tf_custom_palettes',
    LOCALE: 'proxifier_locale',
    PROFILE: 'proxifier_active_profile',
    EXPERIENCE_MODE: 'proxifier_ux_mode',
    WIZARD_COMPLETED: 'proxifier_wizard_done'
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
  SIMULATION_PRESETS: [
    {
      processName: 'firefox.exe',
      processPath: 'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
      targetHost: 'api.github.com',
      targetPort: 443,
      protocol: 'tcp' as const
    },
    {
      processName: 'curl',
      processPath: '/usr/bin/curl',
      targetHost: 'stealth.torproject.org',
      targetPort: 443,
      protocol: 'tcp' as const
    },
    {
      processName: 'updater.exe',
      processPath: 'C:\\ProgramData\\App\\updater.exe',
      targetHost: 'events.telemetry.example.com',
      targetPort: 443,
      protocol: 'tcp' as const
    }
  ]
} as const;
