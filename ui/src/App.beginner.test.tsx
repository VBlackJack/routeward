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
import i18n from './i18n';
import { App } from './App';
import { UI_CONFIG } from './config/constants';
import { ThemeForgeProvider } from './theme/ThemeForgeContext';
import { HttpResponseError, routewardClient } from './services/ipc';
import { SystemDiagnostics } from './types/routeward';

function renderApp() {
  return render(
    <ThemeForgeProvider>
      <App />
    </ThemeForgeProvider>
  );
}

function diagnostics(overrides: Partial<SystemDiagnostics>): SystemDiagnostics {
  return {
    daemonConnected: true,
    running: true,
    osName: 'WINDOWS',
    interceptionMode: 'hybrid',
    elevatedPrivileges: true,
    relayTcpEndpoint: '127.0.0.1:10808',
    relayHttpEndpoint: '127.0.0.1:10809',
    dnsEndpoint: '127.0.0.1:5353',
    fakeIpCidr: '198.18.0.0/15',
    activeLocale: 'en',
    pausedUntilEpochMs: null,
    autoStartErrorKey: null,
    ...overrides
  };
}

describe('App: beginner UX flows', () => {
  beforeEach(async () => {
    window.localStorage.clear();
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.LOCALE, 'en');
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.EXPERIENCE_MODE, 'simple');
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.WIZARD_COMPLETED, 'true');
    await i18n.changeLanguage('en');
    vi.spyOn(routewardClient, 'startRealtimeStream').mockImplementation(() => {});
    vi.spyOn(routewardClient, 'getPacStatus').mockImplementation(() => new Promise(() => {}));
    vi.spyOn(routewardClient, 'getAutostartStatus').mockImplementation(
      () => new Promise(() => {})
    );
    vi.spyOn(routewardClient, 'getSystemProxyStatus').mockImplementation(
      () => new Promise(() => {})
    );
    vi.spyOn(routewardClient, 'listNamedProfiles').mockImplementation(
      () => new Promise(() => {})
    );
    vi.spyOn(routewardClient, 'getCurrentNetworkInfo').mockImplementation(
      () => new Promise(() => {})
    );
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('never shows the raw technical message of a failed call', async () => {
    vi.spyOn(routewardClient, 'upsertRule').mockRejectedValue(
      new HttpResponseError(500, 'os error 2: No such file or directory')
    );
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue(diagnostics({}));
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    renderApp();
    fireEvent.keyDown(window, { key: '2', altKey: true });
    fireEvent.click(await screen.findByLabelText(i18n.t('rules.simple.pack_lan_title')));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(i18n.t('app.toast.error.generic'));
    expect(alert).not.toHaveTextContent(/os error/i);
    expect(warn).toHaveBeenCalled();
  });

  it('shows a plain-language pill and hero state for a paused protection and resumes with a start', async () => {
    const until = new Date(2030, 0, 1, 9, 30, 0).getTime();
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue(
      diagnostics({ running: false, pausedUntilEpochMs: until })
    );
    const toggleSpy = vi.spyOn(routewardClient, 'toggleEngine').mockResolvedValue(
      diagnostics({})
    );
    renderApp();
    expect(
      screen.getByText(i18n.t('dashboard.health.paused.pill', { time: '09:30' }))
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('dashboard.simple.resume_now') })
    );
    await waitFor(() => expect(toggleSpy).toHaveBeenCalledWith(true));
  });

  it('pauses through the daemon with the chosen length, with no timer in the page', async () => {
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue(diagnostics({}));
    const pauseSpy = vi
      .spyOn(routewardClient, 'pauseEngine')
      .mockResolvedValue(diagnostics({ running: false, pausedUntilEpochMs: Date.now() + 900_000 }));
    renderApp();
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('dashboard.simple.pause_15m') })
    );
    await waitFor(() => expect(pauseSpy).toHaveBeenCalledWith(15 * 60));
  });

  it('starts only the service on the very first run and opens the setup assistant', async () => {
    window.localStorage.removeItem(UI_CONFIG.STORAGE_KEYS.WIZARD_COMPLETED);
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue(
      diagnostics({ daemonConnected: false, running: false, elevatedPrivileges: false })
    );
    const startSpy = vi
      .spyOn(routewardClient, 'startDaemon')
      .mockResolvedValue({ connected: true });
    const toggleSpy = vi.spyOn(routewardClient, 'toggleEngine');
    renderApp();

    // The Simple home hides the service banner: only the hero offers a start.
    expect(
      screen.getAllByRole('button', { name: i18n.t('app.header.engine.start_protection') })
    ).toHaveLength(1);
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('app.header.engine.start_protection') })
    );
    await waitFor(() => expect(startSpy).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(toggleSpy).not.toHaveBeenCalled();
    // One-time notice about the background service.
    expect(screen.getByText(i18n.t('app.service_notice.title'))).toBeInTheDocument();
  });

  it('closing the setup assistant does not mark it as completed', async () => {
    window.localStorage.removeItem(UI_CONFIG.STORAGE_KEYS.WIZARD_COMPLETED);
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue(diagnostics({}));
    renderApp();
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('app.titlebar.close') }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(window.localStorage.getItem(UI_CONFIG.STORAGE_KEYS.WIZARD_COMPLETED)).not.toBe('true');
  });

  it('offers a button on the non-elevated banner that calls the daemon start route', async () => {
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue(
      diagnostics({ elevatedPrivileges: false })
    );
    const startSpy = vi
      .spyOn(routewardClient, 'startDaemon')
      .mockResolvedValue({ connected: true });
    renderApp();
    expect(screen.getByText(i18n.t('app.daemon_banner.not_elevated_title'))).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('app.daemon_banner.not_elevated_button') })
    );
    await waitFor(() => expect(startSpy).toHaveBeenCalledTimes(1));
  });

  it('shows the translated automatic start error on the home page', async () => {
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue(
      diagnostics({
        running: false,
        autoStartErrorKey: 'errors.interceptor.driver_missing'
      })
    );
    renderApp();
    expect(screen.getByText(new RegExp(i18n.t('errors.interceptor.driver_missing').slice(0, 30)))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('app.auto_start_error.title'))).toBeInTheDocument();
  });

  it('hides expert commands from the palette in Simple mode', async () => {
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue(diagnostics({}));
    renderApp();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(
      screen.getByText(i18n.t('command_palette.actions.toggle_engine'))
    ).toBeInTheDocument();
    expect(
      screen.queryByText(i18n.t('command_palette.actions.flush_dns'))
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(i18n.t('command_palette.actions.test_all_proxies'))
    ).not.toBeInTheDocument();
  });

  it('asks before turning the all-in-one shield on, then offers an undo', async () => {
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue(diagnostics({}));
    vi.spyOn(routewardClient, 'getProfile').mockReturnValue({
      ...routewardClient.getProfile(),
      securityPolicy: {
        killSwitchEnabled: false,
        blockUdpOnTcpOnlyProxy: true,
        strictDnsNoLocalFallback: false,
        blockQuicUdp443: false,
        blockEncryptedDnsBypass: false
      }
    });
    const updateSpy = vi
      .spyOn(routewardClient, 'updateSecurityPolicy')
      .mockResolvedValue(routewardClient.getProfile());
    renderApp();
    fireEvent.keyDown(window, { key: '5', altKey: true });
    fireEvent.click(
      await screen.findByLabelText(i18n.t('settings.security.simple_shield_title'))
    );
    expect(updateSpy).not.toHaveBeenCalled();
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('dashboard.confirm.apply') }));
    await waitFor(() => expect(updateSpy).toHaveBeenCalledTimes(1));
    fireEvent.click(await screen.findByRole('button', { name: i18n.t('app.toast.undo') }));
    await waitFor(() => expect(updateSpy).toHaveBeenCalledTimes(2));
    expect(updateSpy.mock.calls[1][0]).toMatchObject({ killSwitchEnabled: false });
  });
});
