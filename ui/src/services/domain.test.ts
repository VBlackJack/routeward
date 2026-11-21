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
import { normalizeDomainPatterns } from './domain';

describe('normalizeDomainPatterns', () => {
  it('keeps plain domains, wildcards, and negations untouched', () => {
    const res = normalizeDomainPatterns('meshcore.net, *.meshcore.net, !*.local');
    expect(res.normalizedFromUrl).toBe(false);
    expect(res.primaryDomain).toBeNull();
    expect(res.patterns).toEqual(['meshcore.net', '*.meshcore.net', '!*.local']);
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
