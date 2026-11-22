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

import { UI_CONFIG } from '../config/constants';

export type SupportedLocale = (typeof UI_CONFIG.SUPPORTED_LOCALES)[number];

function isSupportedLocale(value: string | null | undefined): value is SupportedLocale {
  return (UI_CONFIG.SUPPORTED_LOCALES as readonly string[]).includes(value ?? '');
}

/**
 * Picks the interface language. A language the user saved always wins; without one, the
 * browser language decides (any French variant gives French, everything else gives English).
 */
export function resolveInitialLocale(
  savedLocale: string | null | undefined,
  navigatorLanguage: string | null | undefined
): SupportedLocale {
  if (isSupportedLocale(savedLocale)) {
    return savedLocale;
  }
  const browserLanguage = (navigatorLanguage ?? '').trim().toLowerCase();
  if (!browserLanguage) {
    return UI_CONFIG.DEFAULT_LOCALE;
  }
  return browserLanguage.startsWith('fr') ? 'fr' : 'en';
}

/** Reads the saved language (when storage works) and the browser language of this window. */
export function detectInitialLocale(): SupportedLocale {
  if (typeof window === 'undefined') {
    return UI_CONFIG.DEFAULT_LOCALE;
  }
  let saved: string | null = null;
  try {
    saved = window.localStorage.getItem(UI_CONFIG.STORAGE_KEYS.LOCALE);
  } catch {
    saved = null;
  }
  const navigatorLanguage =
    typeof navigator !== 'undefined' ? navigator.language : undefined;
  return resolveInitialLocale(saved, navigatorLanguage);
}
