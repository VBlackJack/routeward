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

import React, { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Trash2 } from 'lucide-react';
import { LogEntry, LogLevel } from '../types/routeward';

interface LogsViewProps {
  logs: LogEntry[];
  onClear: () => void;
}

export const LogsView: React.FC<LogsViewProps> = ({ logs, onClear }) => {
  const { t } = useTranslation();
  const [levelFilter, setLevelFilter] = useState<'ALL' | LogLevel>('ALL');

  const filtered = useMemo(() => {
    if (levelFilter === 'ALL') return logs;
    return logs.filter((l) => l.level === levelFilter);
  }, [logs, levelFilter]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          {(['ALL', 'INFO', 'WARN', 'ERROR'] as const).map((lvl) => (
            <button
              key={lvl}
              onClick={() => setLevelFilter(lvl)}
              className={`rounded-tf-md px-3 py-1.5 text-xs font-semibold transition ${
                levelFilter === lvl
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
          onClick={onClear}
          className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs text-tf-secondary hover:text-tf-red"
        >
          <Trash2 className="h-3.5 w-3.5" />
          {t('logs.toolbar.clear')}
        </button>
      </div>

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
            {filtered.length === 0 ? (
              <tr>
                <td
                  colSpan={4}
                  className="px-4 py-8 text-center font-sans text-tf-secondary"
                >
                  {t('logs.table.empty')}
                </td>
              </tr>
            ) : (
              filtered.map((entry) => (
                <tr
                  key={entry.id}
                  className="transition hover:bg-tf-surface-alt/40"
                >
                  <td className="whitespace-nowrap px-4 py-2.5 text-[11px] text-tf-secondary">
                    {new Date(entry.timestamp).toLocaleTimeString()}
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
                      {entry.level}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-tf-accent">
                    {entry.component}
                  </td>
                  <td className="px-4 py-2.5 text-tf-primary">
                    {entry.message}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
