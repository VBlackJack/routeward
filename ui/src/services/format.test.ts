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

import { afterEach, describe, expect, it } from 'vitest';
import i18n from '../i18n';
import { formatBytes, formatLogTime, formatSampleTime } from './format';

const KIB = 1024;
const MIB = KIB * KIB;
const GIB = MIB * KIB;

describe('localized formats', () => {
  const initialLanguage = i18n.language;

  afterEach(async () => {
    await i18n.changeLanguage(initialLanguage);
  });

  it('formats bytes with English units and a dot decimal', async () => {
    await i18n.changeLanguage('en');
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(5 * MIB)).toBe('5.0 MB');
    expect(formatBytes(2.5 * GIB)).toBe('2.5 GB');
  });

  it('formats bytes with French units and a comma decimal', async () => {
    await i18n.changeLanguage('fr');
    expect(formatBytes(0)).toBe('0 o');
    expect(formatBytes(512)).toBe('512 o');
    expect(formatBytes(1536)).toBe('1,5 Ko');
    expect(formatBytes(5 * MIB)).toBe('5,0 Mo');
    expect(formatBytes(2.5 * GIB)).toBe('2,5 Go');
  });

  it('never groups digits and clamps to the largest unit', async () => {
    await i18n.changeLanguage('fr');
    expect(formatBytes(1023 * KIB)).toBe('1023,0 Ko');
    expect(formatBytes(4096 * GIB)).toBe('4096,0 Go');
  });

  it('treats negative and non-finite values as zero', async () => {
    await i18n.changeLanguage('en');
    expect(formatBytes(-5)).toBe('0 B');
    expect(formatBytes(Number.NaN)).toBe('0 B');
    expect(formatBytes(Number.POSITIVE_INFINITY)).toBe('0 B');
  });

  it('formats an ISO log timestamp with the app locale', async () => {
    const iso = '2026-11-17T09:05:07Z';
    const date = new Date(iso);
    await i18n.changeLanguage('en');
    expect(formatLogTime(iso)).toBe(
      new Intl.DateTimeFormat('en', { timeStyle: 'medium' }).format(date)
    );
    await i18n.changeLanguage('fr');
    expect(formatLogTime(iso)).toBe(
      new Intl.DateTimeFormat('fr', { timeStyle: 'medium' }).format(date)
    );
  });

  it('returns an unparsable log timestamp unchanged', () => {
    expect(formatLogTime('not-a-date')).toBe('not-a-date');
  });

  it('converts the UTC sampler time of day to local time', async () => {
    await i18n.changeLanguage('en');
    const now = new Date(Date.UTC(2026, 10, 17, 12, 0, 0));
    const expected = new Intl.DateTimeFormat('en', { timeStyle: 'medium' }).format(
      new Date(Date.UTC(2026, 10, 17, 9, 5, 7))
    );
    expect(formatSampleTime('09:05:07', now)).toBe(expected);
  });

  it('pluralizes counts in English', async () => {
    await i18n.changeLanguage('en');
    expect(i18n.t('connections.simple.count_connections', { count: 1 })).toBe('1 connection');
    expect(i18n.t('connections.simple.count_connections', { count: 2 })).toBe('2 connections');
    expect(i18n.t('proxies.section.chains.hops', { count: 1 })).toBe('1 node');
    expect(i18n.t('settings.profiles.proxies_count', { count: 0 })).toBe('0 proxies');
    expect(i18n.t('settings.profiles.rules_count', { count: 1 })).toBe('1 rule');
  });

  it('pluralizes counts in French, where zero is singular', async () => {
    await i18n.changeLanguage('fr');
    expect(i18n.t('connections.simple.count_connections', { count: 0 })).toBe('0 connexion');
    expect(i18n.t('connections.simple.count_connections', { count: 3 })).toBe('3 connexions');
    expect(i18n.t('settings.profiles.rules_count', { count: 1 })).toBe('1 règle');
    expect(i18n.t('settings.profiles.rules_count', { count: 2 })).toBe('2 règles');
  });

  it('returns a sample timestamp of another shape unchanged', () => {
    expect(formatSampleTime('yesterday')).toBe('yesterday');
    expect(formatSampleTime('9:05')).toBe('9:05');
  });
});
