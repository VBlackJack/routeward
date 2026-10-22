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

import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import enTranslation from '../../../locales/en.json';
import frTranslation from '../../../locales/fr.json';
import { UI_CONFIG } from '../config/constants';

const savedLocale =
  typeof window !== 'undefined'
    ? window.localStorage.getItem(UI_CONFIG.STORAGE_KEYS.LOCALE) ||
      UI_CONFIG.DEFAULT_LOCALE
    : UI_CONFIG.DEFAULT_LOCALE;

i18n.use(initReactI18next).init({
  resources: {
    en: { translation: enTranslation },
    fr: { translation: frTranslation }
  },
  lng: savedLocale,
  fallbackLng: 'en',
  interpolation: {
    escapeValue: false
  }
});

export default i18n;
