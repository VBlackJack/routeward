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
import { UI_CONFIG } from '../config/constants';
import { LogEntry } from '../types/routeward';
import {
  buildQueryLogsRequest,
  EMPTY_LOG_FILTER,
  filterFromJump,
  filterLogEntries,
  formatLogFileDate
} from './logQuery';

const CENTER = Date.parse('2026-11-22T10:00:00Z');

function entry(partial: Partial<LogEntry> & { id: string }): LogEntry {
  return {
    timestamp: '2026-11-22T10:00:00Z',
    level: 'INFO',
    component: 'engine',
    message: 'hello',
    ...partial
  };
}

describe('filterLogEntries', () => {
  const entries = [
    entry({ id: '1', level: 'DEBUG', message: 'debug line' }),
    entry({ id: '2', level: 'INFO', message: 'Proxy connected', component: 'proxy' }),
    entry({ id: '3', level: 'WARN', message: 'slow' }),
    entry({ id: '4', level: 'ERROR', message: 'proxy down', component: 'proxy' })
  ];

  it('keeps the level and above', () => {
    const warn = filterLogEntries(entries, { ...EMPTY_LOG_FILTER, level: 'WARN' });
    expect(warn.map((e) => e.id)).toEqual(['3', '4']);
  });

  it('searches the message and component text, ignoring case', () => {
    const found = filterLogEntries(entries, { ...EMPTY_LOG_FILTER, text: 'PROXY' });
    expect(found.map((e) => e.id)).toEqual(['2', '4']);
  });

  it('filters on one component', () => {
    const found = filterLogEntries(entries, { ...EMPTY_LOG_FILTER, component: 'engine' });
    expect(found.map((e) => e.id)).toEqual(['1', '3']);
  });

  it('keeps only the last period', () => {
    const old = entry({ id: 'old', timestamp: '2026-11-22T08:00:00Z' });
    const recent = entry({ id: 'new', timestamp: '2026-11-22T09:50:00Z' });
    const found = filterLogEntries(
      [old, recent],
      { ...EMPTY_LOG_FILTER, rangeMs: UI_CONFIG.LOG_TIME_RANGE_MS.LAST_HOUR },
      CENTER
    );
    expect(found.map((e) => e.id)).toEqual(['new']);
  });
});

describe('jump from a connection', () => {
  it('filters on the connection id within +/- the named window', () => {
    const filter = filterFromJump({
      connectionId: 'abcdef12-0000',
      pid: 42,
      centerMs: CENTER,
      nonce: 1
    });
    expect(filter.window).toEqual({
      since: CENTER - UI_CONFIG.LOG_JUMP_WINDOW_MS,
      until: CENTER + UI_CONFIG.LOG_JUMP_WINDOW_MS
    });
    expect(UI_CONFIG.LOG_JUMP_WINDOW_MS).toBe(30000);

    const inside = entry({
      id: 'in',
      timestamp: '2026-11-22T10:00:20Z',
      context: { connectionId: 'abcdef12-0000' }
    });
    const prefix = entry({
      id: 'prefix',
      timestamp: '2026-11-22T10:00:05Z',
      context: { connectionId: 'abcdef12' }
    });
    const outside = entry({
      id: 'out',
      timestamp: '2026-11-22T10:01:00Z',
      context: { connectionId: 'abcdef12-0000' }
    });
    const other = entry({
      id: 'other',
      timestamp: '2026-11-22T10:00:01Z',
      context: { connectionId: 'zzzzzzzz' }
    });
    const none = entry({ id: 'none', timestamp: '2026-11-22T10:00:01Z' });
    const found = filterLogEntries([inside, prefix, outside, other, none], filter);
    expect(found.map((e) => e.id)).toEqual(['in', 'prefix']);
  });

  it('falls back to the pid when there is no connection id', () => {
    const filter = filterFromJump({ pid: 42, centerMs: CENTER, nonce: 2 });
    expect(filter.pid).toBe(42);
    expect(filter.connectionId).toBeUndefined();
  });
});

describe('buildQueryLogsRequest', () => {
  it('sends the same filters to the daemon file query', () => {
    const filter = {
      ...filterFromJump({ connectionId: 'abc', pid: 7, centerMs: CENTER, nonce: 1 }),
      text: ' timeout ',
      level: 'WARN' as const,
      component: 'proxy'
    };
    expect(buildQueryLogsRequest(filter, '20261122', 'cur-1', CENTER)).toEqual({
      source: { daemonFile: { date: '20261122' } },
      limit: UI_CONFIG.LOG_QUERY_PAGE_SIZE,
      minLevel: 'WARN',
      components: ['proxy'],
      text: 'timeout',
      connectionId: 'abc',
      since: CENTER - UI_CONFIG.LOG_JUMP_WINDOW_MS,
      until: CENTER + UI_CONFIG.LOG_JUMP_WINDOW_MS,
      cursor: 'cur-1'
    });
  });

  it('omits empty filters and formats file dates', () => {
    expect(buildQueryLogsRequest(EMPTY_LOG_FILTER, '20261122', undefined, CENTER)).toEqual({
      source: { daemonFile: { date: '20261122' } },
      limit: UI_CONFIG.LOG_QUERY_PAGE_SIZE
    });
    expect(formatLogFileDate('20261122')).toBe('2026-11-22');
    expect(formatLogFileDate('weird')).toBe('weird');
  });
});
