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

import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Activity,
  Command,
  Globe,
  LayoutDashboard,
  Palette,
  Power,
  Search,
  Server,
  Settings,
  Shield,
  Zap
} from 'lucide-react';
import { useThemeForge } from '../theme/ThemeForgeContext';
import { ModalContainer } from './ModalContainer';
import { ExperienceMode } from './QuickSetupWizardModal';

export type NavTabId = 'home' | 'apps' | 'proxy' | 'activity' | 'settings';

interface CommandPaletteModalProps {
  /** Simple mode hides the commands that need networking vocabulary. */
  experienceMode?: ExperienceMode;
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
  /** Hidden from the list in Simple mode. */
  expertOnly?: boolean;
  group: string;
  label: string;
  badge?: string;
  swatchHex?: string;
  icon: React.FC<{ className?: string }>;
  onSelect: () => void;
}

export const CommandPaletteModal: React.FC<CommandPaletteModalProps> = ({
  experienceMode = 'expert',
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
  const titleId = useId();
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
        id: 'nav-home',
        group: navGroup,
        label: t('app.nav.home.tab'),
        badge: 'Alt+1',
        icon: LayoutDashboard,
        onSelect: () => onNavigate('home')
      },
      {
        id: 'nav-apps',
        group: navGroup,
        label: t('app.nav.apps.tab'),
        badge: 'Alt+2',
        icon: Shield,
        onSelect: () => onNavigate('apps')
      },
      {
        id: 'nav-proxy',
        group: navGroup,
        label: t('app.nav.proxy.tab'),
        badge: 'Alt+3',
        icon: Server,
        onSelect: () => onNavigate('proxy')
      },
      {
        id: 'nav-activity',
        group: navGroup,
        label: t('app.nav.activity.tab'),
        badge: 'Alt+4',
        icon: Activity,
        onSelect: () => onNavigate('activity')
      },
      {
        id: 'nav-settings',
        group: navGroup,
        label: t('app.nav.settings.tab'),
        badge: 'Alt+5',
        icon: Settings,
        onSelect: () => onNavigate('settings')
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
        expertOnly: true,
        group: actGroup,
        label: t('command_palette.actions.test_all_proxies'),
        icon: Zap,
        onSelect: onTestAllProxies
      },
      {
        id: 'act-killswitch',
        expertOnly: true,
        group: actGroup,
        label: t('command_palette.actions.toggle_killswitch'),
        icon: Shield,
        onSelect: onToggleKillSwitch
      },
      {
        id: 'act-flush-dns',
        expertOnly: true,
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

    const everything = [...navItems, ...actionItems, ...themeItems];
    return experienceMode === 'simple'
      ? everything.filter((item) => !item.expertOnly)
      : everything;
  }, [
    t,
    experienceMode,
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

  const listboxId = useId();
  const itemRefs = useRef<Array<HTMLButtonElement | null>>([]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  useEffect(() => {
    itemRefs.current[selectedIndex]?.scrollIntoView?.({ block: 'nearest' });
  }, [selectedIndex, filteredItems.length]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
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

  const activeOptionId =
    filteredItems.length > 0 && selectedIndex < filteredItems.length
      ? `${listboxId}-opt-${selectedIndex}`
      : undefined;

  return (
    <ModalContainer onClose={onClose} alignTop labelledBy={titleId}>
      <div
        className="tf-card w-full max-w-xl overflow-hidden shadow-2xl"
        onKeyDown={handleKeyDown}
      >
        <h2 id={titleId} className="sr-only">
          {t('command_palette.modal.title')}
        </h2>
        <div className="flex items-center border-b border-tf-border px-4 py-3 focus-within:ring-2 focus-within:ring-inset focus-within:ring-tf-accent">
          <Search className="mr-3 h-4 w-4 text-tf-accent" />
          <input
            name="command-palette-query"
            ref={inputRef}
            type="text"
            role="combobox"
            aria-expanded={filteredItems.length > 0}
            aria-controls={listboxId}
            aria-autocomplete="list"
            aria-activedescendant={activeOptionId}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('command_palette.modal.search_placeholder')}
            aria-label={t('command_palette.modal.search_placeholder')}
            className="w-full bg-transparent text-sm text-tf-primary focus:outline-none"
          />
          <span className="rounded bg-tf-surface-alt px-2 py-0.5 font-mono text-[10px] text-tf-secondary">
            ESC
          </span>
        </div>

        <div
          id={listboxId}
          role="listbox"
          aria-label={t('command_palette.modal.title')}
          className="max-h-96 overflow-y-auto p-2"
        >
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
                  id={`${listboxId}-opt-${idx}`}
                  ref={(el) => {
                    itemRefs.current[idx] = el;
                  }}
                  type="button"
                  role="option"
                  aria-selected={isSelected}
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
    </ModalContainer>
  );
};
