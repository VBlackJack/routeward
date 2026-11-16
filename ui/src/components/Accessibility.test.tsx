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
import { afterEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import { HelpTooltip } from './HelpTooltip';
import { ModalContainer } from './ModalContainer';
import { ProxiesView } from './ProxiesView';
import { ProxyNode } from '../types/routeward';

describe('Modal focus management', () => {
  afterEach(() => {
    cleanup();
  });

  it('cycles Tab and Shift+Tab inside the dialog and restores focus on close', () => {
    const opener = document.createElement('button');
    document.body.appendChild(opener);
    opener.focus();

    const { unmount } = render(
      <ModalContainer onClose={() => {}} labelledBy="t">
        <h2 id="t">Title</h2>
        <button type="button">First</button>
        <button type="button">Middle</button>
        <button type="button">Last</button>
      </ModalContainer>
    );

    const dialog = screen.getByRole('dialog');
    expect(dialog.className).not.toContain('contents');
    const first = screen.getByRole('button', { name: 'First' });
    const last = screen.getByRole('button', { name: 'Last' });
    expect(first).toHaveFocus();

    last.focus();
    fireEvent.keyDown(window, { key: 'Tab' });
    expect(first).toHaveFocus();

    fireEvent.keyDown(window, { key: 'Tab', shiftKey: true });
    expect(last).toHaveFocus();

    unmount();
    expect(opener).toHaveFocus();
    opener.remove();
  });

  it('closes a HelpTooltip with Escape without closing the surrounding modal', () => {
    const onClose = vi.fn();
    render(
      <ModalContainer onClose={onClose} labelledBy="t">
        <h2 id="t">Title</h2>
        <HelpTooltip text="Explains the field" />
      </ModalContainer>
    );
    const help = screen.getByRole('button', { name: 'Explains the field' });
    fireEvent.focus(help);
    expect(screen.getByRole('tooltip')).toBeInTheDocument();

    fireEvent.keyDown(help, { key: 'Escape' });
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();

    fireEvent.keyDown(help, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe('ProxiesView form accessibility and edit fidelity', () => {
  afterEach(() => {
    cleanup();
  });

  const importedProxy: ProxyNode = {
    id: 'p-sni',
    name: 'Imported TLS',
    protocol: 'https',
    host: 'edge.example.net',
    port: 443,
    auth: null,
    udpEnabled: false,
    tls: true,
    tlsSkipVerify: false,
    sni: 'front.example.org',
    enabled: false,
    lastLatencyMs: null,
    exitIp: null
  };

  it('labels form fields and keeps an imported SNI and enabled flag when editing', () => {
    const onAddProxy = vi.fn();
    render(
      <ProxiesView
        proxies={[importedProxy]}
        chains={[]}
        experienceMode="expert"
        onTestProxy={vi.fn().mockResolvedValue(undefined)}
        onTestAllProxies={vi.fn().mockResolvedValue(undefined)}
        onAddProxy={onAddProxy}
        onImportUris={vi.fn()}
        onCopyUri={vi.fn()}
        onRemoveProxy={vi.fn()}
        onAddChain={vi.fn()}
        onRemoveChain={vi.fn()}
      />
    );

    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('proxies.card.action.edit') })
    );
    expect(
      screen.getByLabelText(i18n.t('proxies.modal.add_proxy.name_label'))
    ).toHaveValue('Imported TLS');
    expect(
      screen.getByLabelText(i18n.t('proxies.modal.add_proxy.host_label'))
    ).toHaveValue('edge.example.net');
    expect(
      screen.getByLabelText(i18n.t('proxies.modal.add_proxy.port_label'))
    ).toHaveValue(443);

    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('proxies.modal.add_proxy.submit') })
    );
    expect(onAddProxy).toHaveBeenCalledTimes(1);
    expect(onAddProxy.mock.calls[0][0]).toMatchObject({
      id: 'p-sni',
      sni: 'front.example.org',
      enabled: false
    });
  });
});
