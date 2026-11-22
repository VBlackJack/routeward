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

import { describe, expect, it } from 'vitest';
import { resolveInitialLocale } from './locale';

describe('resolveInitialLocale', () => {
  it('keeps the language the user saved', () => {
    expect(resolveInitialLocale('en', 'fr-FR')).toBe('en');
    expect(resolveInitialLocale('fr', 'en-US')).toBe('fr');
  });

  it('follows a French browser language when nothing was saved', () => {
    expect(resolveInitialLocale(null, 'fr-CA')).toBe('fr');
    expect(resolveInitialLocale(null, 'FR')).toBe('fr');
  });

  it('uses English for any other browser language', () => {
    expect(resolveInitialLocale(null, 'de-DE')).toBe('en');
    expect(resolveInitialLocale('xx', 'en-GB')).toBe('en');
  });

  it('falls back to the default language when the browser gives none', () => {
    expect(resolveInitialLocale(null, undefined)).toBe('fr');
    expect(resolveInitialLocale(null, '')).toBe('fr');
  });
});
