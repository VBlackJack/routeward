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

/// <reference types="vite/client" />

import { describe, expect, it } from 'vitest';

const sources = import.meta.glob(['../**/*.tsx', '!../**/*.test.tsx'], {
  query: '?raw',
  import: 'default',
  eager: true
}) as Record<string, string>;

const CONTROL_START = /<(input|select|textarea)\b/g;
const ID_OR_NAME = /\s(id|name)=/;

/** Returns the JSX opening tag that starts at `start`, honouring braces and quotes. */
function readOpeningTag(source: string, start: number): string {
  let depth = 0;
  let quote: string | null = null;
  for (let i = start; i < source.length; i += 1) {
    const ch = source[i];
    if (quote) {
      if (ch === quote && source[i - 1] !== '\\') quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || (depth > 0 && ch === '`')) {
      quote = ch;
    } else if (ch === '{') {
      depth += 1;
    } else if (ch === '}') {
      depth -= 1;
    } else if (depth === 0 && ch === '>') {
      return source.slice(start, i + 1);
    }
  }
  return source.slice(start);
}

describe('form controls', () => {
  it('scans the component sources', () => {
    const files = Object.keys(sources);
    expect(files).toContain('./SettingsView.tsx');
    expect(files).toContain('./ProcessLauncherModal.tsx');
    expect(files).toContain('../App.tsx');
  });

  it('gives every input, select and textarea an id or a name', () => {
    const offenders: string[] = [];
    let controls = 0;
    for (const [file, source] of Object.entries(sources)) {
      for (const match of source.matchAll(CONTROL_START)) {
        controls += 1;
        const tag = readOpeningTag(source, match.index ?? 0);
        if (!ID_OR_NAME.test(tag)) {
          const line = source.slice(0, match.index).split('\n').length;
          offenders.push(`${file}:${line}`);
        }
      }
    }
    expect(controls).toBeGreaterThan(0);
    expect(offenders).toEqual([]);
  });
});
