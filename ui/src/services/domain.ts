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

export interface NormalizedDomainResult {
  patterns: string[];
  normalizedFromUrl: boolean;
  primaryDomain: string | null;
}

const URL_LIKE_PATTERN = /^(?:https?:\/\/|www\.)/i;
const PATH_OR_QUERY_PATTERN = /[/?#]/;

/**
 * Normalizes comma-separated domain entries. Plain patterns (`*.example.com`,
 * `example.com`, `!*.local`) are preserved as-is; pasted URLs such as
 * `https://www.example.com/login` expand to `example.com` and `*.example.com`.
 */
export function normalizeDomainPatterns(raw: string): NormalizedDomainResult {
  const parts = raw
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);

  const patterns: string[] = [];
  const seen = new Set<string>();
  let normalizedFromUrl = false;
  let primaryDomain: string | null = null;

  const pushUnique = (value: string) => {
    const key = value.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      patterns.push(value);
    }
  };

  for (const part of parts) {
    if (part.startsWith('!') || part.includes('*')) {
      pushUnique(part);
      continue;
    }

    const looksLikeUrl =
      URL_LIKE_PATTERN.test(part) || PATH_OR_QUERY_PATTERN.test(part);
    if (!looksLikeUrl) {
      pushUnique(part);
      continue;
    }

    const candidate = /^https?:\/\//i.test(part) ? part : `https://${part}`;
    try {
      const parsed = new URL(candidate);
      const rawHost = parsed.hostname.toLowerCase().replace(/\.$/, '');
      if (!rawHost) {
        pushUnique(part);
        continue;
      }
      const baseHost = rawHost.startsWith('www.') ? rawHost.slice(4) : rawHost;
      if (!baseHost || !baseHost.includes('.')) {
        pushUnique(rawHost);
        continue;
      }
      normalizedFromUrl = true;
      if (!primaryDomain) {
        primaryDomain = baseHost;
      }
      pushUnique(baseHost);
      pushUnique(`*.${baseHost}`);
    } catch {
      pushUnique(part);
    }
  }

  return { patterns, normalizedFromUrl, primaryDomain };
}
