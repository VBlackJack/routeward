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
import './i18n';
import { App } from './App';
import { UI_CONFIG } from './config/constants';
import { ThemeForgeProvider } from './theme/ThemeForgeContext';
import { routewardClient } from './services/ipc';

function renderApp() {
  return render(
    <ThemeForgeProvider>
      <App />
    </ThemeForgeProvider>
  );
}

describe('App navigation and accessible modals', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.EXPERIENCE_MODE, 'simple');
    vi.spyOn(routewardClient, 'startRealtimeStream').mockImplementation(() => {});
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('renders 5 use-case tabs, keeps Simple mode calm, and supports Alt+1..5 navigation', () => {
    renderApp();

    const tablist = screen.getByRole('tablist');
    expect(tablist).toBeInTheDocument();

    const tabs = screen.getAllByRole('tab');
    expect(tabs).toHaveLength(5);
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true');

    // Bottom technical footer and ThemeForge header clutter are absent in Simple mode
    expect(screen.queryByRole('contentinfo')).not.toBeInTheDocument();

    // Alt+1..5 switches through all 5 tabs in both modes
    fireEvent.keyDown(window, { key: '5', altKey: true });
    expect(screen.getAllByRole('tab')[4]).toHaveAttribute('aria-selected', 'true');

    fireEvent.keyDown(window, { key: '2', altKey: true });
    expect(screen.getAllByRole('tab')[1]).toHaveAttribute('aria-selected', 'true');

    // Switching to Advanced mode reveals the persistent technical footer
    fireEvent.click(screen.getByRole('button', { pressed: false, name: /avanc|advanced/i }));
    expect(screen.getByRole('contentinfo')).toBeInTheDocument();
  });

  it('opens ThemeForge modal from Settings tab with ARIA dialog attributes and closes on Escape', () => {
    renderApp();

    fireEvent.keyDown(window, { key: '5', altKey: true });

    const themeButton = screen.getByRole('button', { name: /themeforge/i });
    fireEvent.click(themeButton);

    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
