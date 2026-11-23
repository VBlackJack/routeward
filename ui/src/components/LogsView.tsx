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

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Search, Trash2, X } from 'lucide-react';
import { UI_CONFIG } from '../config/constants';
import { formatLogTime } from '../services/format';
import {
  buildQueryLogsRequest,
  EMPTY_LOG_FILTER,
  filterFromJump,
  filterLogEntries,
  formatLogFileDate,
  LogFilter,
  LogsJump
} from '../services/logQuery';
import {
  LogEntry,
  LogLevel,
  QueryLogsRequest,
  QueryLogsResponse
} from '../types/routeward';

/** Value of the source selector for the live memory log. */
const SOURCE_MEMORY = 'memory';

const TIME_RANGE_OPTIONS = [
  { value: UI_CONFIG.LOG_TIME_RANGE_MS.ALL, labelKey: 'logs.query.range_all' },
  { value: UI_CONFIG.LOG_TIME_RANGE_MS.LAST_15_MIN, labelKey: 'logs.query.range_15min' },
  { value: UI_CONFIG.LOG_TIME_RANGE_MS.LAST_HOUR, labelKey: 'logs.query.range_1h' },
  { value: UI_CONFIG.LOG_TIME_RANGE_MS.LAST_DAY, labelKey: 'logs.query.range_24h' }
] as const;

interface LogsViewProps {
  logs: LogEntry[];
  onClear: () => void;
  /** Reads logs from the daemon (memory or files by date); without it only the live list is offered. */
  onQuery?: (req: QueryLogsRequest) => Promise<QueryLogsResponse>;
  /** Opens the view already filtered on one connection and the moment it happened. */
  jump?: LogsJump | null;
}

export const LogsView: React.FC<LogsViewProps> = ({
  logs,
  onClear,
  onQuery,
  jump = null
}) => {
  const { t } = useTranslation();
  const [filter, setFilter] = useState<LogFilter>(EMPTY_LOG_FILTER);
  const [textInput, setTextInput] = useState('');
  const [source, setSource] = useState<string>(SOURCE_MEMORY);
  const [availableDates, setAvailableDates] = useState<string[]>([]);
  const [fileEntries, setFileEntries] = useState<LogEntry[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>(undefined);
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(false);
  const [queryError, setQueryError] = useState(false);
  const requestSeq = useRef(0);
  const appliedJump = useRef<number | null>(null);

  useEffect(() => {
    if (!jump || appliedJump.current === jump.nonce) {
      return;
    }
    appliedJump.current = jump.nonce;
    setFilter(filterFromJump(jump));
    setTextInput('');
    setSource(SOURCE_MEMORY);
  }, [jump]);

  useEffect(() => {
    if (!onQuery) {
      return;
    }
    let cancelled = false;
    onQuery({ source: 'memory', limit: 1 })
      .then((res) => {
        if (!cancelled) setAvailableDates(res.availableDates ?? []);
      })
      .catch(() => {
        if (!cancelled) setAvailableDates([]);
      });
    return () => {
      cancelled = true;
    };
  }, [onQuery]);

  const runFileQuery = (cursor?: string) => {
    if (!onQuery || source === SOURCE_MEMORY) {
      return;
    }
    const seq = ++requestSeq.current;
    setLoading(true);
    setQueryError(false);
    onQuery(buildQueryLogsRequest(filter, source, cursor))
      .then((res) => {
        if (seq !== requestSeq.current) return;
        setFileEntries((prev) => (cursor ? [...prev, ...res.entries] : res.entries));
        setNextCursor(res.nextCursor);
        setTruncated(res.truncated);
        if (res.availableDates?.length) setAvailableDates(res.availableDates);
      })
      .catch(() => {
        if (seq !== requestSeq.current) return;
        setQueryError(true);
        if (!cursor) setFileEntries([]);
        setNextCursor(undefined);
      })
      .finally(() => {
        if (seq === requestSeq.current) setLoading(false);
      });
  };

  useEffect(() => {
    if (source === SOURCE_MEMORY) {
      requestSeq.current += 1;
      setFileEntries([]);
      setNextCursor(undefined);
      setTruncated(false);
      setQueryError(false);
      setLoading(false);
      return;
    }
    runFileQuery();
    // The query re-runs when its inputs change; runFileQuery is recreated every render on purpose.
  }, [source, filter, onQuery]);

  const liveEntries = useMemo(
    () => filterLogEntries(logs, filter),
    [logs, filter]
  );
  const shown = source === SOURCE_MEMORY ? liveEntries : fileEntries;

  const components = useMemo(() => {
    const names = new Set<string>();
    for (const entry of source === SOURCE_MEMORY ? logs : fileEntries) {
      names.add(entry.component);
    }
    if (filter.component) names.add(filter.component);
    return Array.from(names).sort();
  }, [logs, fileEntries, source, filter.component]);

  const updateFilter = (patch: Partial<LogFilter>) =>
    setFilter((prev) => ({ ...prev, ...patch }));

  const clearJump = () =>
    setFilter((prev) => ({
      ...prev,
      connectionId: undefined,
      pid: undefined,
      window: undefined
    }));

  const jumpActive = Boolean(filter.connectionId || filter.pid !== undefined || filter.window);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          {(['ALL', 'INFO', 'WARN', 'ERROR'] as const).map((lvl) => (
            <button
              key={lvl}
              type="button"
              aria-pressed={filter.level === lvl}
              onClick={() => updateFilter({ level: lvl })}
              className={`rounded-tf-md px-3 py-1.5 text-xs font-semibold transition ${
                filter.level === lvl
                  ? 'bg-tf-accent text-tf-bg'
                  : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
              }`}
            >
              {lvl === 'ALL'
                ? t('logs.toolbar.filter_all')
                : t(`logs.toolbar.filter_${lvl.toLowerCase()}`)}
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={onClear}
          className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs text-tf-secondary hover:text-tf-red"
        >
          <Trash2 className="h-3.5 w-3.5" />
          {t('logs.toolbar.clear')}
        </button>
      </div>

      <form
        role="search"
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          updateFilter({ text: textInput });
        }}
      >
        <label className="relative min-w-[220px] flex-1 text-[11px] text-tf-secondary">
          <span className="mb-1 block">{t('logs.query.search_label')}</span>
          <Search className="absolute left-3 top-[30px] h-4 w-4 text-tf-secondary" />
          <input
            name="logs-search"
            type="search"
            value={textInput}
            onChange={(e) => setTextInput(e.target.value)}
            placeholder={t('logs.query.search_placeholder')}
            className="tf-input w-full py-2 pl-9 pr-4 text-sm"
          />
        </label>
        <label className="text-[11px] text-tf-secondary">
          <span className="mb-1 block">{t('logs.query.component_label')}</span>
          <select
            name="logs-component"
            value={filter.component}
            onChange={(e) => updateFilter({ component: e.target.value })}
            className="tf-input px-2 py-2 text-xs"
          >
            <option value="">{t('logs.query.component_all')}</option>
            {components.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <label className="text-[11px] text-tf-secondary">
          <span className="mb-1 block">{t('logs.query.range_label')}</span>
          <select
            name="logs-range"
            value={filter.rangeMs}
            disabled={Boolean(filter.window)}
            onChange={(e) => updateFilter({ rangeMs: Number(e.target.value) })}
            className="tf-input px-2 py-2 text-xs"
          >
            {TIME_RANGE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {t(opt.labelKey)}
              </option>
            ))}
          </select>
        </label>
        {onQuery && (
          <label className="text-[11px] text-tf-secondary">
            <span className="mb-1 block">{t('logs.query.source_label')}</span>
            <select
              name="logs-source"
              value={source}
              onChange={(e) => setSource(e.target.value)}
              className="tf-input px-2 py-2 text-xs"
            >
              <option value={SOURCE_MEMORY}>{t('logs.query.source_memory')}</option>
              {availableDates.map((date) => (
                <option key={date} value={date}>
                  {t('logs.query.source_file', { date: formatLogFileDate(date) })}
                </option>
              ))}
            </select>
          </label>
        )}
        <button type="submit" className="tf-btn-accent px-4 py-2 text-xs font-bold">
          {t('logs.query.search_button')}
        </button>
      </form>

      {jumpActive && (
        <div className="flex flex-wrap items-center gap-2 rounded-tf-md border border-tf-cyan/30 bg-tf-cyan/10 px-3 py-2 text-xs text-tf-primary">
          <span>
            {t('logs.query.jump_active', {
              seconds: UI_CONFIG.LOG_JUMP_WINDOW_MS / 1000
            })}
          </span>
          <button
            type="button"
            onClick={clearJump}
            className="flex items-center gap-1 font-semibold text-tf-cyan hover:underline"
          >
            <X className="h-3 w-3" />
            {t('logs.query.jump_clear')}
          </button>
        </div>
      )}

      {queryError && (
        <p role="alert" className="text-xs text-tf-red">
          {t('logs.query.error')}
        </p>
      )}
      {source !== SOURCE_MEMORY && truncated && (
        <p className="text-[11px] text-tf-secondary">{t('logs.query.truncated')}</p>
      )}

      <div className="tf-card overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-tf-border bg-tf-surface-alt text-[11px] uppercase tracking-wider text-tf-secondary">
            <tr>
              <th className="px-4 py-3">{t('logs.table.timestamp')}</th>
              <th className="px-4 py-3">{t('logs.table.level')}</th>
              <th className="px-4 py-3">{t('logs.table.component')}</th>
              <th className="px-4 py-3">{t('logs.table.message')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-tf-border font-mono">
            {shown.length === 0 ? (
              <tr>
                <td
                  colSpan={4}
                  className="px-4 py-8 text-center font-sans text-tf-secondary"
                >
                  {loading ? t('logs.query.loading') : t('logs.table.empty')}
                </td>
              </tr>
            ) : (
              (source === SOURCE_MEMORY
                ? shown.slice(0, UI_CONFIG.MAX_RENDERED_TABLE_ROWS)
                : shown
              ).map((entry, index) => (
                <tr
                  key={`${entry.id}-${index}`}
                  className="transition hover:bg-tf-surface-alt/40"
                >
                  <td className="whitespace-nowrap px-4 py-2.5 text-[11px] text-tf-secondary">
                    {formatLogTime(entry.timestamp)}
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                        entry.level === 'ERROR'
                          ? 'bg-tf-red/20 text-tf-red'
                          : entry.level === 'WARN'
                            ? 'bg-tf-orange/20 text-tf-orange'
                            : 'bg-tf-cyan/20 text-tf-cyan'
                      }`}
                    >
                      {entry.level as LogLevel}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-tf-accent">
                    {entry.component}
                  </td>
                  <td className="px-4 py-2.5 text-tf-primary">
                    {entry.message}
                    {entry.context?.pid !== undefined && (
                      <span className="ml-2 text-[10px] text-tf-secondary">
                        {t('logs.query.context_pid', { pid: entry.context.pid })}
                      </span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {source !== SOURCE_MEMORY && nextCursor && (
        <div className="flex justify-center">
          <button
            type="button"
            disabled={loading}
            onClick={() => runFileQuery(nextCursor)}
            className="tf-surface-alt px-4 py-2 text-xs font-semibold text-tf-primary hover:border-tf-accent"
          >
            {loading ? t('logs.query.loading') : t('logs.query.load_more')}
          </button>
        </div>
      )}
    </div>
  );
};
