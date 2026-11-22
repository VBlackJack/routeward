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

export interface NormalizedDomainResult {
  patterns: string[];
  normalizedFromUrl: boolean;
  /** True when a bare hostname was widened to also cover its subdomains. */
  coversSubdomains: boolean;
  primaryDomain: string | null;
}

const URL_LIKE_PATTERN = /^(?:https?:\/\/|www\.)/i;
const PATH_OR_QUERY_PATTERN = /[/?#]/;
const HOSTNAME_PATTERN = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/i;
const PATH_SEPARATOR_PATTERN = /[\\/]/;
const WWW_PREFIX = 'www.';

/**
 * Normalizes comma-separated domain entries. Patterns that already carry a wildcard or a
 * negation (`*.example.com`, `!*.local`) are preserved as-is; pasted URLs such as
 * `https://www.example.com/login` expand to `example.com` and `*.example.com`; a bare
 * hostname such as `example.com` becomes `*.example.com`, which the engine and the PAC file
 * both match for the apex and for every subdomain.
 */
export function normalizeDomainPatterns(raw: string): NormalizedDomainResult {
  const parts = raw
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);

  const patterns: string[] = [];
  const seen = new Set<string>();
  let normalizedFromUrl = false;
  let coversSubdomains = false;
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
      const bareHost = part.toLowerCase().replace(/\.$/, '');
      if (HOSTNAME_PATTERN.test(bareHost)) {
        coversSubdomains = true;
        if (!primaryDomain) {
          primaryDomain = bareHost;
        }
        pushUnique(`*.${bareHost}`);
      } else {
        pushUnique(part);
      }
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

  return { patterns, normalizedFromUrl, coversSubdomains, primaryDomain };
}

/** Returns the hosts a site check should evaluate: the bare host and its `www.` variant. */
export function expandSiteCheckHosts(host: string): string[] {
  const clean = host.trim().toLowerCase().replace(/^\*\./, '');
  if (!clean) {
    return [];
  }
  if (!HOSTNAME_PATTERN.test(clean)) {
    return [clean];
  }
  const bare = clean.startsWith(WWW_PREFIX) ? clean.slice(WWW_PREFIX.length) : clean;
  return bare.includes('.') ? [bare, `${WWW_PREFIX}${bare}`] : [clean];
}

/** True when the daemon reports Windows, or (without daemon info) the browser user agent does. */
export function isWindowsPlatform(osName?: string | null): boolean {
  if (osName) {
    return osName.toUpperCase() === UI_CONFIG.WINDOWS_OS_NAME;
  }
  if (typeof navigator === 'undefined') {
    return false;
  }
  return UI_CONFIG.WINDOWS_USER_AGENT_PATTERN.test(navigator.userAgent || '');
}

/**
 * Appends `.exe` to an application name typed without extension on Windows
 * (`spotify` -> `spotify.exe`). Wildcards, paths, negations and names that
 * already contain a dot are left untouched.
 */
export function normalizeProcessName(raw: string, windows: boolean): string {
  const name = raw.trim();
  if (
    !windows ||
    !name ||
    name.startsWith('!') ||
    name.includes('*') ||
    name.includes('.') ||
    PATH_SEPARATOR_PATTERN.test(name)
  ) {
    return name;
  }
  return `${name}${UI_CONFIG.WINDOWS_EXECUTABLE_SUFFIX}`;
}

/** Splits a comma-separated application list and normalizes every entry (see `normalizeProcessName`). */
export function normalizeProcessList(raw: string, windows: boolean): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of raw.split(',')) {
    const name = normalizeProcessName(part, windows);
    const key = name.toLowerCase();
    if (name && !seen.has(key)) {
      seen.add(key);
      out.push(name);
    }
  }
  return out;
}
