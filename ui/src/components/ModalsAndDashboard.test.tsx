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

import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import { ThemeForgeProvider } from '../theme/ThemeForgeContext';
import { CommandPaletteModal } from './CommandPaletteModal';
import { ThemeForgeModal } from './ThemeForgeModal';

describe('CommandPaletteModal', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('en');
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('exposes combobox/listbox semantics and navigates options with keyboard', () => {
    const onClose = vi.fn();
    const onNavigate = vi.fn();
    render(
      <ThemeForgeProvider>
        <CommandPaletteModal
          experienceMode="expert"
          onClose={onClose}
          onNavigate={onNavigate}
          onToggleEngine={vi.fn()}
          onTestAllProxies={vi.fn()}
          onFlushDns={vi.fn()}
          onToggleKillSwitch={vi.fn()}
          onOpenThemeForge={vi.fn()}
          onSwitchLanguage={vi.fn()}
        />
      </ThemeForgeProvider>
    );

    const input = screen.getByRole('combobox');
    const listbox = screen.getByRole('listbox');
    expect(input).toHaveAttribute('aria-controls', listbox.id);

    const options = screen.getAllByRole('option');
    expect(options.length).toBeGreaterThan(3);
    expect(options[0]).toHaveAttribute('aria-selected', 'true');

    fireEvent.keyDown(input, { key: 'ArrowDown' });
    expect(options[1]).toHaveAttribute('aria-selected', 'true');
    expect(input).toHaveAttribute('aria-activedescendant', options[1].id);

    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onNavigate).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('filters commands and closes on Escape', () => {
    const onClose = vi.fn();
    render(
      <ThemeForgeProvider>
        <CommandPaletteModal
          experienceMode="simple"
          onClose={onClose}
          onNavigate={vi.fn()}
          onToggleEngine={vi.fn()}
          onTestAllProxies={vi.fn()}
          onFlushDns={vi.fn()}
          onToggleKillSwitch={vi.fn()}
          onOpenThemeForge={vi.fn()}
          onSwitchLanguage={vi.fn()}
        />
      </ThemeForgeProvider>
    );

    const input = screen.getByRole('combobox');
    fireEvent.change(input, { target: { value: 'zzzz-no-match' } });
    expect(screen.queryAllByRole('option')).toHaveLength(0);
    expect(screen.getByText(i18n.t('command_palette.modal.empty'))).toBeInTheDocument();

    fireEvent.keyDown(input, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe('ThemeForgeModal', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('en');
    window.localStorage.clear();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('switches palette and closes cleanly', () => {
    const onClose = vi.fn();
    render(
      <ThemeForgeProvider>
        <ThemeForgeModal onClose={onClose} />
      </ThemeForgeProvider>
    );

    const dialog = screen.getByRole('dialog');
    expect(dialog).toBeInTheDocument();

    const buttons = screen.getAllByRole('button');
    expect(buttons.length).toBeGreaterThan(4);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
