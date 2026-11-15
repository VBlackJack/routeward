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
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './i18n';
import { App } from './App';
import { UI_CONFIG } from './config/constants';
import { ThemeForgeProvider } from './theme/ThemeForgeContext';
import { routewardClient, HttpResponseError } from './services/ipc';

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
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.WIZARD_COMPLETED, 'true');
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

  it('auto-opens first-run wizard only after daemon connects and triggers 1-click service start on Windows', async () => {
    window.localStorage.removeItem(UI_CONFIG.STORAGE_KEYS.WIZARD_COMPLETED);
    const getDiagSpy = vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue({
      daemonConnected: false,
      running: false,
      osName: 'WINDOWS',
      interceptionMode: 'hybrid',
      elevatedPrivileges: false,
      relayTcpEndpoint: '127.0.0.1:10808',
      relayHttpEndpoint: '127.0.0.1:10809',
      dnsEndpoint: '127.0.0.1:5353',
      fakeIpCidr: '198.18.0.0/15',
      activeLocale: 'fr'
    });
    const startDaemonSpy = vi
      .spyOn(routewardClient, 'startDaemon')
      .mockResolvedValue({ connected: true });

    renderApp();

    // Never auto-open wizard over disconnected banner
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    const startBtn = screen.getByRole('button', {
      name: /démarrer le service|start service/i
    });
    fireEvent.click(startBtn);
    await waitFor(() => expect(startDaemonSpy).toHaveBeenCalledTimes(1));

    // Once connected on first run, Quick Setup Wizard auto-opens
    getDiagSpy.mockReturnValue({
      daemonConnected: true,
      running: false,
      osName: 'WINDOWS',
      interceptionMode: 'hybrid',
      elevatedPrivileges: true,
      relayTcpEndpoint: '127.0.0.1:10808',
      relayHttpEndpoint: '127.0.0.1:10809',
      dnsEndpoint: '127.0.0.1:5353',
      fakeIpCidr: '198.18.0.0/15',
      activeLocale: 'fr'
    });
    cleanup();
    renderApp();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('shows specific localized toast when elevated daemon rejects insecure profile directory', async () => {
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue({
      daemonConnected: false,
      running: false,
      osName: 'WINDOWS',
      interceptionMode: 'hybrid',
      elevatedPrivileges: false,
      relayTcpEndpoint: '127.0.0.1:10808',
      relayHttpEndpoint: '127.0.0.1:10809',
      dnsEndpoint: '127.0.0.1:5353',
      fakeIpCidr: '198.18.0.0/15',
      activeLocale: 'fr'
    });
    vi.spyOn(routewardClient, 'startDaemon').mockRejectedValue(
      new HttpResponseError(
        422,
        'Insecure ACL on %ProgramData%\\RouteWard',
        'insecure_profile'
      )
    );

    renderApp();

    const startBtn = screen.getByRole('button', {
      name: /démarrer le service|start service/i
    });
    fireEvent.click(startBtn);

    await waitFor(() => {
      expect(
        screen.getByText(/droits ou propriétaire non sécurisés|insecure ownership or permissions/i)
      ).toBeInTheDocument();
    });
  });
});
