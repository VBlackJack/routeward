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
    window.localStorage.setItem('routeward_experience_mode', 'simple');
    vi.spyOn(routewardClient, 'startRealtimeStream').mockImplementation(() => {});
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('renders accessible tablist semantics and blocks expert tabs on Alt+5/Alt+6 in simple mode', () => {
    renderApp();

    const tablist = screen.getByRole('tablist');
    expect(tablist).toBeInTheDocument();

    const tabs = screen.getAllByRole('tab');
    expect(tabs).toHaveLength(4);
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true');

    fireEvent.keyDown(window, { key: '5', altKey: true });
    expect(screen.getAllByRole('tab')[0]).toHaveAttribute('aria-selected', 'true');

    fireEvent.keyDown(window, { key: '6', altKey: true });
    expect(screen.getAllByRole('tab')[0]).toHaveAttribute('aria-selected', 'true');
  });

  it('opens ThemeForge modal with ARIA dialog attributes and closes on Escape', () => {
    renderApp();

    const themeButton = screen.getByRole('button', { name: /themeforge/i });
    fireEvent.click(themeButton);

    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
