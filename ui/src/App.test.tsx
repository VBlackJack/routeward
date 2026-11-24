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
    vi.spyOn(routewardClient, 'getPacStatus').mockImplementation(
      () => new Promise(() => {})
    );
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
    fireEvent.click(screen.getByRole('button', { pressed: false, name: /expert/i }));
    expect(screen.getByRole('contentinfo')).toBeInTheDocument();
  });

  it('opens ThemeForge modal from Settings tab with ARIA dialog attributes and closes on Escape', async () => {
    renderApp();

    fireEvent.keyDown(window, { key: '5', altKey: true });

    const themeButton = screen.getByRole('button', { name: /themeforge/i });
    fireEvent.click(themeButton);

    const dialog = await screen.findByRole('dialog');
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
      activeLocale: 'fr',
      pausedUntilEpochMs: null,
      autoStartErrorKey: null
    });
    const startDaemonSpy = vi
      .spyOn(routewardClient, 'startDaemon')
      .mockResolvedValue({ connected: true });

    renderApp();

    // Never auto-open wizard over disconnected banner
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    const startBtn = screen.getByRole('button', {
      name: /démarrer la protection|start protection/i
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
      activeLocale: 'fr',
      pausedUntilEpochMs: null,
      autoStartErrorKey: null
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
      activeLocale: 'fr',
      pausedUntilEpochMs: null,
      autoStartErrorKey: null
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
      name: /démarrer la protection|start protection/i
    });
    fireEvent.click(startBtn);

    await waitFor(() => {
      expect(
        screen.getByText(/dossier de données|data folder/i)
      ).toBeInTheDocument();
    });
  });

  it.each([
    ['linux_group_required', 409, /usermod -aG routeward/],
    ['linux_service_not_running', 503, /systemctl enable --now routeward/],
    ['unsupported_os', 501, /RouteWard could not start\. Try again\.|RouteWard n'a pas pu démarrer\. Réessayez\./]
  ])('shows the matching text on Linux when the daemon start fails with %s', async (errorKey, status, expected) => {
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue({
      daemonConnected: false,
      running: false,
      osName: 'LINUX',
      interceptionMode: 'hybrid',
      elevatedPrivileges: false,
      relayTcpEndpoint: '127.0.0.1:10808',
      relayHttpEndpoint: '127.0.0.1:10809',
      dnsEndpoint: '127.0.0.1:5353',
      fakeIpCidr: '198.18.0.0/15',
      activeLocale: 'fr',
      pausedUntilEpochMs: null,
      autoStartErrorKey: null
    });
    vi.spyOn(routewardClient, 'startDaemon').mockRejectedValue(
      new HttpResponseError(status, 'daemon start failed', errorKey)
    );

    renderApp();

    fireEvent.click(
      screen.getByRole('button', { name: /démarrer la protection|start protection/i })
    );

    await waitFor(() => {
      expect(screen.getByText(expected)).toBeInTheDocument();
    });
  });

  it('offers the start action and both Linux steps when the service is unreachable on Linux', async () => {
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.LOCALE, 'en');
    await i18n.changeLanguage('en');
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue({
      daemonConnected: false,
      running: false,
      osName: 'LINUX',
      interceptionMode: 'hybrid',
      elevatedPrivileges: false,
      relayTcpEndpoint: '127.0.0.1:10808',
      relayHttpEndpoint: '127.0.0.1:10809',
      dnsEndpoint: '127.0.0.1:5353',
      fakeIpCidr: '198.18.0.0/15',
      activeLocale: 'en',
      pausedUntilEpochMs: null,
      autoStartErrorKey: null
    });
    const startDaemonSpy = vi
      .spyOn(routewardClient, 'startDaemon')
      .mockRejectedValue(
        new HttpResponseError(409, 'group required', 'linux_group_required')
      );

    renderApp();

    expect(
      screen.getAllByText(/sudo systemctl enable --now routeward/).length
    ).toBeGreaterThan(0);
    expect(screen.getAllByText(/sudo usermod -aG routeward \$USER/).length).toBeGreaterThan(0);
    fireEvent.click(
      screen.getAllByRole('button', { name: /start protection/i })[0]
    );
    await waitFor(() => expect(startDaemonSpy).toHaveBeenCalledTimes(1));
  });

  it('shows a persistent translated error toast, not a success toast, when adding a proxy fails', async () => {
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.LOCALE, 'en');
    await i18n.changeLanguage('en');
    const upsertSpy = vi
      .spyOn(routewardClient, 'upsertProxy')
      .mockRejectedValue(
        new HttpResponseError(400, 'Invalid proxy URI format', 'errors.proxy.invalid_uri')
      );

    renderApp();
    fireEvent.keyDown(window, { key: '3', altKey: true });
    fireEvent.click(
      await screen.findByRole('button', {
        name: i18n.t('proxies.simple.add')
      })
    );
    fireEvent.change(screen.getByLabelText(i18n.t('proxies.modal.add_proxy.name_label')), {
      target: { value: 'Broken' }
    });
    fireEvent.change(screen.getByLabelText(i18n.t('proxies.modal.add_proxy.host_label')), {
      target: { value: '127.0.0.1' }
    });
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('proxies.modal.add_proxy.submit') })
    );

    await waitFor(() => expect(upsertSpy).toHaveBeenCalledTimes(1));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(i18n.t('errors.proxy.invalid_uri'));
    expect(screen.queryByText(i18n.t('app.toast.proxy.added'))).not.toBeInTheDocument();

    // Error toasts are not auto-dismissed and can be closed explicitly
    await new Promise((resolve) => setTimeout(resolve, UI_CONFIG.TOAST_DURATION_MS + 200));
    expect(screen.getByRole('alert')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('app.toast.dismiss') }));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  }, 10000);

  it('shows the success toast only after the mutation resolved', async () => {
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.LOCALE, 'en');
    await i18n.changeLanguage('en');
    let resolveUpsert: (value: ReturnType<typeof routewardClient.getProfile>) => void =
      () => {};
    vi.spyOn(routewardClient, 'upsertProxy').mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveUpsert = resolve;
        })
    );

    renderApp();
    fireEvent.keyDown(window, { key: '3', altKey: true });
    fireEvent.click(
      await screen.findByRole('button', {
        name: i18n.t('proxies.simple.add')
      })
    );
    fireEvent.change(screen.getByLabelText(i18n.t('proxies.modal.add_proxy.name_label')), {
      target: { value: 'Ok' }
    });
    fireEvent.change(screen.getByLabelText(i18n.t('proxies.modal.add_proxy.host_label')), {
      target: { value: '127.0.0.1' }
    });
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('proxies.modal.add_proxy.submit') })
    );

    expect(screen.queryByText(i18n.t('app.toast.proxy.added'))).not.toBeInTheDocument();
    resolveUpsert(routewardClient.getProfile());
    expect(await screen.findByText(i18n.t('app.toast.proxy.added'))).toBeInTheDocument();
  });

  it('starts the service and enables protection in one click from Home when disconnected on Windows', async () => {
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.LOCALE, 'en');
    await i18n.changeLanguage('en');
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
      activeLocale: 'en',
      pausedUntilEpochMs: null,
      autoStartErrorKey: null
    });
    const startDaemonSpy = vi
      .spyOn(routewardClient, 'startDaemon')
      .mockResolvedValue({ connected: true });
    const toggleEngineSpy = vi
      .spyOn(routewardClient, 'toggleEngine')
      .mockResolvedValue({
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
        autoStartErrorKey: null
      });

    renderApp();

    const startProtectionBtn = screen.getByRole('button', {
      name: i18n.t('app.header.engine.start_protection')
    });
    fireEvent.click(startProtectionBtn);

    await waitFor(() => expect(startDaemonSpy).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(toggleEngineSpy).toHaveBeenCalledWith(true));
  });
});
