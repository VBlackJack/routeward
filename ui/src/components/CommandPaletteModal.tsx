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
import {
  Activity,
  Command,
  FileText,
  Globe,
  LayoutDashboard,
  Palette,
  Power,
  Search,
  Server,
  Shield,
  Zap
} from 'lucide-react';
import { useThemeForge } from '../theme/ThemeForgeContext';

export type NavTabId =
  | 'dashboard'
  | 'connections'
  | 'proxies'
  | 'rules'
  | 'dns'
  | 'logs';

interface CommandPaletteModalProps {
  onClose: () => void;
  onNavigate: (tab: NavTabId) => void;
  onToggleEngine: () => void;
  onTestAllProxies: () => void;
  onFlushDns: () => void;
  onToggleKillSwitch: () => void;
  onOpenThemeForge: () => void;
  onSwitchLanguage: () => void;
}

interface PaletteItem {
  id: string;
  group: string;
  label: string;
  badge?: string;
  swatchHex?: string;
  icon: React.FC<{ className?: string }>;
  onSelect: () => void;
}

export const CommandPaletteModal: React.FC<CommandPaletteModalProps> = ({
  onClose,
  onNavigate,
  onToggleEngine,
  onTestAllProxies,
  onFlushDns,
  onToggleKillSwitch,
  onOpenThemeForge,
  onSwitchLanguage
}) => {
  const { t } = useTranslation();
  const { palettes, setTheme } = useThemeForge();
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const allItems = useMemo<PaletteItem[]>(() => {
    const navGroup = t('command_palette.modal.group_navigation');
    const actGroup = t('command_palette.modal.group_actions');
    const themeGroup = t('command_palette.modal.group_themes');

    const navItems: PaletteItem[] = [
      {
        id: 'nav-dashboard',
        group: navGroup,
        label: t('app.nav.dashboard.tab'),
        badge: 'Alt+1',
        icon: LayoutDashboard,
        onSelect: () => onNavigate('dashboard')
      },
      {
        id: 'nav-connections',
        group: navGroup,
        label: t('app.nav.connections.tab'),
        badge: 'Alt+2',
        icon: Activity,
        onSelect: () => onNavigate('connections')
      },
      {
        id: 'nav-proxies',
        group: navGroup,
        label: t('app.nav.proxies.tab'),
        badge: 'Alt+3',
        icon: Server,
        onSelect: () => onNavigate('proxies')
      },
      {
        id: 'nav-rules',
        group: navGroup,
        label: t('app.nav.rules.tab'),
        badge: 'Alt+4',
        icon: Shield,
        onSelect: () => onNavigate('rules')
      },
      {
        id: 'nav-dns',
        group: navGroup,
        label: t('app.nav.dns.tab'),
        badge: 'Alt+5',
        icon: Globe,
        onSelect: () => onNavigate('dns')
      },
      {
        id: 'nav-logs',
        group: navGroup,
        label: t('app.nav.logs.tab'),
        badge: 'Alt+6',
        icon: FileText,
        onSelect: () => onNavigate('logs')
      }
    ];

    const actionItems: PaletteItem[] = [
      {
        id: 'act-toggle-engine',
        group: actGroup,
        label: t('command_palette.actions.toggle_engine'),
        icon: Power,
        onSelect: onToggleEngine
      },
      {
        id: 'act-test-proxies',
        group: actGroup,
        label: t('command_palette.actions.test_all_proxies'),
        icon: Zap,
        onSelect: onTestAllProxies
      },
      {
        id: 'act-killswitch',
        group: actGroup,
        label: t('command_palette.actions.toggle_killswitch'),
        icon: Shield,
        onSelect: onToggleKillSwitch
      },
      {
        id: 'act-flush-dns',
        group: actGroup,
        label: t('command_palette.actions.flush_dns'),
        icon: Globe,
        onSelect: onFlushDns
      },
      {
        id: 'act-themeforge',
        group: actGroup,
        label: t('command_palette.actions.open_themeforge'),
        icon: Palette,
        onSelect: onOpenThemeForge
      },
      {
        id: 'act-lang',
        group: actGroup,
        label: t('command_palette.actions.switch_language'),
        icon: Command,
        onSelect: onSwitchLanguage
      }
    ];

    const themeItems: PaletteItem[] = palettes.map((pal) => ({
      id: `theme-${pal.name}`,
      group: themeGroup,
      label: `ThemeForge: ${pal.displayName} (${pal.family})`,
      badge: pal.colors.Background,
      swatchHex: pal.colors.Accent,
      icon: Palette,
      onSelect: () => setTheme(pal.name)
    }));

    return [...navItems, ...actionItems, ...themeItems];
  }, [
    t,
    palettes,
    onNavigate,
    onToggleEngine,
    onTestAllProxies,
    onFlushDns,
    onToggleKillSwitch,
    onOpenThemeForge,
    onSwitchLanguage,
    setTheme
  ]);

  const filteredItems = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return allItems;
    return allItems.filter(
      (item) =>
        item.label.toLowerCase().includes(q) ||
        item.group.toLowerCase().includes(q)
    );
  }, [allItems, query]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) =>
        filteredItems.length > 0 ? (prev + 1) % filteredItems.length : 0
      );
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) =>
        filteredItems.length > 0
          ? (prev - 1 + filteredItems.length) % filteredItems.length
          : 0
      );
    } else if (e.key === 'Enter' && filteredItems[selectedIndex]) {
      e.preventDefault();
      filteredItems[selectedIndex].onSelect();
      onClose();
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 pt-20 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="tf-card w-full max-w-xl overflow-hidden shadow-2xl"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        <div className="flex items-center border-b border-tf-border px-4 py-3">
          <Search className="mr-3 h-4 w-4 text-tf-accent" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('command_palette.modal.search_placeholder')}
            className="w-full bg-transparent text-sm text-tf-primary focus:outline-none"
          />
          <span className="rounded bg-tf-surface-alt px-2 py-0.5 font-mono text-[10px] text-tf-secondary">
            ESC
          </span>
        </div>

        <div className="max-h-96 overflow-y-auto p-2">
          {filteredItems.length === 0 ? (
            <div className="py-8 text-center text-xs text-tf-secondary">
              {t('command_palette.modal.empty')}
            </div>
          ) : (
            filteredItems.map((item, idx) => {
              const Icon = item.icon;
              const isSelected = idx === selectedIndex;
              return (
                <button
                  key={item.id}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  onClick={() => {
                    item.onSelect();
                    onClose();
                  }}
                  className={`flex w-full items-center justify-between rounded-tf-md px-3 py-2 text-left text-xs transition ${
                    isSelected
                      ? 'bg-tf-surface-alt text-tf-primary'
                      : 'text-tf-secondary hover:text-tf-primary'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    {item.swatchHex ? (
                      <span
                        className="h-3.5 w-3.5 rounded-full border border-black/30"
                        style={{ backgroundColor: item.swatchHex }}
                      />
                    ) : (
                      <Icon
                        className={`h-4 w-4 ${
                          isSelected ? 'text-tf-accent' : 'text-tf-secondary'
                        }`}
                      />
                    )}
                    <div>
                      <div className="font-semibold text-tf-primary">
                        {item.label}
                      </div>
                      <div className="text-[10px] text-tf-secondary">
                        {item.group}
                      </div>
                    </div>
                  </div>
                  {item.badge && (
                    <span className="rounded bg-tf-bg px-2 py-0.5 font-mono text-[10px] text-tf-secondary">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
