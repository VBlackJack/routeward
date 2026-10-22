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

import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Globe, Plus, Trash2 } from 'lucide-react';
import { FakeIpEntry } from '../types/proxifier';

interface DnsViewProps {
  entries: FakeIpEntry[];
  onAllocate: (domain: string) => void;
  onFlush: () => void;
}

export const DnsView: React.FC<DnsViewProps> = ({
  entries,
  onAllocate,
  onFlush
}) => {
  const { t } = useTranslation();
  const [domainInput, setDomainInput] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!domainInput.trim()) return;
    onAllocate(domainInput.trim());
    setDomainInput('');
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-bold text-tf-primary">
            {t('dns.header.title')}
          </h2>
          <p className="text-xs text-tf-secondary">
            {t('dns.header.subtitle')}
          </p>
        </div>
        <button
          onClick={onFlush}
          className="tf-surface-alt flex items-center gap-1.5 px-3 py-2 text-xs text-tf-secondary hover:text-tf-red"
        >
          <Trash2 className="h-3.5 w-3.5" />
          {t('dns.header.flush_button')}
        </button>
      </div>

      <form onSubmit={handleSubmit} className="tf-card flex gap-3 p-4">
        <input
          type="text"
          value={domainInput}
          onChange={(e) => setDomainInput(e.target.value)}
          placeholder={t('dns.allocate.placeholder')}
          className="tf-input flex-1 px-3 py-1.5 text-xs"
        />
        <button
          type="submit"
          className="tf-btn-accent flex items-center gap-1.5 px-4 py-1.5 text-xs"
        >
          <Plus className="h-3.5 w-3.5" />
          {t('dns.allocate.submit')}
        </button>
      </form>

      <div className="tf-card overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-tf-border bg-tf-surface-alt text-[11px] uppercase tracking-wider text-tf-secondary">
            <tr>
              <th className="px-4 py-3">{t('dns.table.fake_ip.header')}</th>
              <th className="px-4 py-3">{t('dns.table.domain.header')}</th>
              <th className="px-4 py-3">{t('dns.table.hits.header')}</th>
              <th className="px-4 py-3">{t('dns.table.expires.header')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-tf-border">
            {entries.length === 0 ? (
              <tr>
                <td
                  colSpan={4}
                  className="px-4 py-8 text-center text-tf-secondary"
                >
                  {t('dns.table.empty.message')}
                </td>
              </tr>
            ) : (
              entries.map((entry) => (
                <tr
                  key={entry.fakeIp}
                  className="transition hover:bg-tf-surface-alt/50"
                >
                  <td className="px-4 py-3 font-mono font-bold text-tf-cyan">
                    <span className="inline-flex items-center gap-2">
                      <Globe className="h-3.5 w-3.5 text-tf-accent" />
                      {entry.fakeIp}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-tf-primary">
                    {entry.domain}
                  </td>
                  <td className="px-4 py-3 font-mono text-tf-green">
                    {entry.hits}
                  </td>
                  <td className="px-4 py-3 font-mono text-tf-secondary">
                    {entry.ttlRemainingSeconds}s
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
