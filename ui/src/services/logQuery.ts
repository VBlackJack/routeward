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
import { LogEntry, LogLevel, QueryLogsRequest } from '../types/routeward';

/** Order used to keep "this level and above". */
const LEVEL_RANK: Record<LogLevel, number> = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3
};

/** The filters of the logs screen; the same object drives the live list and the daemon query. */
export interface LogFilter {
  text: string;
  level: 'ALL' | LogLevel;
  /** Empty means every component. */
  component: string;
  /** Only the last N milliseconds; 0 means no limit. Ignored when `window` is set. */
  rangeMs: number;
  connectionId?: string;
  pid?: number;
  /** Fixed time window (epoch milliseconds), set by "See logs" from a connection. */
  window?: { since: number; until: number };
}

/** Where "See logs" sends the person: one connection and the moment it happened. */
export interface LogsJump {
  connectionId?: string;
  pid?: number;
  /** Instant of the event, epoch milliseconds. */
  centerMs: number;
  /** Changes on every request so the same jump can be asked twice. */
  nonce: number;
}

export const EMPTY_LOG_FILTER: LogFilter = {
  text: '',
  level: 'ALL',
  component: '',
  rangeMs: UI_CONFIG.LOG_TIME_RANGE_MS.ALL
};

/** Turns a jump request into a filter: the connection and a window of +/- LOG_JUMP_WINDOW_MS. */
export function filterFromJump(jump: LogsJump): LogFilter {
  return {
    ...EMPTY_LOG_FILTER,
    connectionId: jump.connectionId,
    pid: jump.connectionId ? undefined : jump.pid,
    window: {
      since: jump.centerMs - UI_CONFIG.LOG_JUMP_WINDOW_MS,
      until: jump.centerMs + UI_CONFIG.LOG_JUMP_WINDOW_MS
    }
  };
}

/** The effective [since, until] bounds of a filter, in epoch milliseconds. */
export function resolveTimeBounds(
  filter: LogFilter,
  nowMs: number
): { since?: number; until?: number } {
  if (filter.window) {
    return { since: filter.window.since, until: filter.window.until };
  }
  if (filter.rangeMs > 0) {
    return { since: nowMs - filter.rangeMs };
  }
  return {};
}

/** The file lines carry only the first characters of a connection id, so a prefix match counts. */
function sameConnection(entryId: string | undefined, wanted: string): boolean {
  return (
    entryId !== undefined &&
    entryId.length > 0 &&
    (entryId.startsWith(wanted) || wanted.startsWith(entryId))
  );
}

/** Applies the filter to the live entries (the browser-side twin of the daemon query). */
export function filterLogEntries(
  entries: LogEntry[],
  filter: LogFilter,
  nowMs: number = Date.now()
): LogEntry[] {
  const text = filter.text.trim().toLowerCase();
  const bounds = resolveTimeBounds(filter, nowMs);
  return entries.filter((entry) => {
    if (filter.level !== 'ALL' && LEVEL_RANK[entry.level] < LEVEL_RANK[filter.level]) {
      return false;
    }
    if (
      filter.component &&
      entry.component.toLowerCase() !== filter.component.toLowerCase()
    ) {
      return false;
    }
    if (
      filter.connectionId &&
      !sameConnection(entry.context?.connectionId, filter.connectionId)
    ) {
      return false;
    }
    if (filter.pid !== undefined && entry.context?.pid !== filter.pid) {
      return false;
    }
    if (bounds.since !== undefined || bounds.until !== undefined) {
      const at = Date.parse(entry.timestamp);
      if (!Number.isNaN(at)) {
        if (bounds.since !== undefined && at < bounds.since) return false;
        if (bounds.until !== undefined && at > bounds.until) return false;
      }
    }
    if (text) {
      const haystack = `${entry.message} ${entry.component}`.toLowerCase();
      if (!haystack.includes(text)) {
        return false;
      }
    }
    return true;
  });
}

/** Builds the daemon request that reads one page of one log file with the same filters. */
export function buildQueryLogsRequest(
  filter: LogFilter,
  date: string,
  cursor?: string,
  nowMs: number = Date.now()
): QueryLogsRequest {
  const bounds = resolveTimeBounds(filter, nowMs);
  const req: QueryLogsRequest = {
    source: { daemonFile: { date } },
    limit: UI_CONFIG.LOG_QUERY_PAGE_SIZE
  };
  if (filter.level !== 'ALL') req.minLevel = filter.level;
  if (filter.component) req.components = [filter.component];
  if (filter.text.trim()) req.text = filter.text.trim();
  if (filter.pid !== undefined) req.pid = filter.pid;
  if (filter.connectionId) req.connectionId = filter.connectionId;
  if (bounds.since !== undefined) req.since = bounds.since;
  if (bounds.until !== undefined) req.until = bounds.until;
  if (cursor) req.cursor = cursor;
  return req;
}

/** Formats a yyyyMMdd date from the daemon as yyyy-MM-dd; anything else is returned unchanged. */
export function formatLogFileDate(date: string): string {
  return /^\d{8}$/.test(date)
    ? `${date.slice(0, 4)}-${date.slice(4, 6)}-${date.slice(6, 8)}`
    : date;
}
