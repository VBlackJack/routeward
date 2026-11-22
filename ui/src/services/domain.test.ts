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

import { describe, expect, it, vi } from 'vitest';
import {
  expandSiteCheckHosts,
  isWindowsPlatform,
  normalizeDomainPatterns,
  normalizeProcessList,
  normalizeProcessName
} from './domain';

describe('normalizeDomainPatterns', () => {
  it('keeps plain domains, wildcards, and negations untouched', () => {
    const res = normalizeDomainPatterns('*.meshcore.net, !*.local, localhost, 10.0.0.1');
    expect(res.normalizedFromUrl).toBe(false);
    expect(res.coversSubdomains).toBe(false);
    expect(res.primaryDomain).toBeNull();
    expect(res.patterns).toEqual(['*.meshcore.net', '!*.local', 'localhost', '10.0.0.1']);
  });

  it('widens a bare hostname to its subdomains so www and the apex are both covered', () => {
    const res = normalizeDomainPatterns('exemple.com');
    expect(res.patterns).toEqual(['*.exemple.com']);
    expect(res.coversSubdomains).toBe(true);
    expect(res.normalizedFromUrl).toBe(false);
    expect(res.primaryDomain).toBe('exemple.com');
    expect(normalizeDomainPatterns('Exemple.COM, exemple.com').patterns).toEqual([
      '*.exemple.com'
    ]);
  });

  it('extracts base domain and subdomain wildcard from a full HTTPS URL', () => {
    const res = normalizeDomainPatterns('https://www.my-bank.fr/login?next=/home#top');
    expect(res.normalizedFromUrl).toBe(true);
    expect(res.primaryDomain).toBe('my-bank.fr');
    expect(res.patterns).toEqual(['my-bank.fr', '*.my-bank.fr']);
  });

  it('handles www-prefixed and path-bearing inputs without scheme', () => {
    const res = normalizeDomainPatterns('www.example.org/docs, app.service.io/api');
    expect(res.normalizedFromUrl).toBe(true);
    expect(res.primaryDomain).toBe('example.org');
    expect(res.patterns).toEqual([
      'example.org',
      '*.example.org',
      'app.service.io',
      '*.app.service.io'
    ]);
  });

  it('deduplicates repeated domains cleanly', () => {
    const res = normalizeDomainPatterns('https://example.com/a, https://www.example.com/b');
    expect(res.patterns).toEqual(['example.com', '*.example.com']);
  });
});

describe('site check hosts', () => {
  it('checks the bare host and its www variant', () => {
    expect(expandSiteCheckHosts('exemple.com')).toEqual(['exemple.com', 'www.exemple.com']);
    expect(expandSiteCheckHosts('www.exemple.com')).toEqual([
      'exemple.com',
      'www.exemple.com'
    ]);
    expect(expandSiteCheckHosts('*.exemple.com')).toEqual([
      'exemple.com',
      'www.exemple.com'
    ]);
    expect(expandSiteCheckHosts('10.0.0.1')).toEqual(['10.0.0.1']);
    expect(expandSiteCheckHosts('')).toEqual([]);
  });
});

describe('application names', () => {
  it('appends .exe on Windows only when there is no dot, wildcard or path', () => {
    expect(normalizeProcessName('spotify', true)).toBe('spotify.exe');
    expect(normalizeProcessName('  Spotify ', true)).toBe('Spotify.exe');
    expect(normalizeProcessName('spotify.exe', true)).toBe('spotify.exe');
    expect(normalizeProcessName('spot*', true)).toBe('spot*');
    expect(normalizeProcessName('C:\\Apps\\spotify', true)).toBe('C:\\Apps\\spotify');
    expect(normalizeProcessName('/usr/bin/curl', true)).toBe('/usr/bin/curl');
    expect(normalizeProcessName('!spotify', true)).toBe('!spotify');
    expect(normalizeProcessName('spotify', false)).toBe('spotify');
  });

  it('normalizes and deduplicates a comma-separated list', () => {
    expect(normalizeProcessList('spotify, Spotify.exe, vlc', true)).toEqual([
      'spotify.exe',
      'vlc.exe'
    ]);
    expect(normalizeProcessList(' , ', true)).toEqual([]);
  });

  it('trusts the daemon OS name and falls back to the user agent', () => {
    expect(isWindowsPlatform('WINDOWS')).toBe(true);
    expect(isWindowsPlatform('LINUX')).toBe(false);
    const ua = vi.spyOn(window.navigator, 'userAgent', 'get');
    ua.mockReturnValue('Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
    expect(isWindowsPlatform()).toBe(true);
    ua.mockReturnValue('Mozilla/5.0 (X11; Linux x86_64)');
    expect(isWindowsPlatform()).toBe(false);
    ua.mockRestore();
  });
});
