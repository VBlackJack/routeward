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
import { afterEach, describe, expect, it, vi } from 'vitest';
import { UI_CONFIG } from '../config/constants';
import i18n from '../i18n';
import { formatLauncherArgs, parseLauncherArgs } from '../services/launcher';
import { ProcessLauncherModal } from './ProcessLauncherModal';

describe('parseLauncherArgs', () => {
  it('keeps one argument per line and drops only empty lines', () => {
    expect(parseLauncherArgs('a\n\nb\n')).toEqual(['a', 'b']);
    expect(parseLauncherArgs('')).toEqual([]);
  });

  it('keeps leading and trailing spaces and inner spaces inside a line', () => {
    expect(parseLauncherArgs('  -c \nhello world\n--flag=a b')).toEqual([
      '  -c ',
      'hello world',
      '--flag=a b'
    ]);
  });

  it('accepts Windows and old Mac line breaks', () => {
    expect(parseLauncherArgs('a\r\nb\rc')).toEqual(['a', 'b', 'c']);
  });

  it('round-trips with formatLauncherArgs', () => {
    const args = ['-NoExit', 'two words'];
    expect(parseLauncherArgs(formatLauncherArgs(args))).toEqual(args);
  });
});

describe('ProcessLauncherModal', () => {
  afterEach(() => {
    cleanup();
  });

  function renderModal(onLaunch = vi.fn().mockResolvedValue(undefined)) {
    const onClose = vi.fn();
    render(
      <ProcessLauncherModal
        relayEndpoint="127.0.0.1:10808"
        onLaunch={onLaunch}
        onClose={onClose}
      />
    );
    return { onLaunch, onClose };
  }

  it('offers a labelled multi-line arguments field with help text', () => {
    renderModal();
    const field = screen.getByLabelText(i18n.t('app.launcher.modal.args_label'));
    expect(field.tagName).toBe('TEXTAREA');
    expect(field).toHaveAttribute('name');
    expect(field).toHaveAccessibleDescription(i18n.t('app.launcher.modal.args_help'));
    expect(field).toHaveValue(UI_CONFIG.QUICK_LAUNCH_PRESETS[0].args.join('\n'));
  });

  it('submits one argument per line without splitting on spaces', async () => {
    const { onLaunch, onClose } = renderModal();
    const field = screen.getByLabelText(i18n.t('app.launcher.modal.args_label'));
    fireEvent.change(field, { target: { value: '-c\n\n  hello world \nlast' } });
    fireEvent.click(screen.getByRole('button', { name: i18n.t('app.launcher.modal.submit') }));

    await waitFor(() => expect(onLaunch).toHaveBeenCalledTimes(1));
    expect(onLaunch).toHaveBeenCalledWith(UI_CONFIG.QUICK_LAUNCH_PRESETS[0].exe, [
      '-c',
      '  hello world ',
      'last'
    ]);
    await waitFor(() => expect(onClose).toHaveBeenCalled());
  });

  it('fills the arguments from a preset', async () => {
    const { onLaunch } = renderModal();
    const preset = UI_CONFIG.QUICK_LAUNCH_PRESETS.find((p) => p.exe === 'powershell.exe');
    expect(preset).toBeDefined();
    fireEvent.click(screen.getByRole('button', { name: 'powershell.exe' }));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('app.launcher.modal.submit') }));

    await waitFor(() => expect(onLaunch).toHaveBeenCalledTimes(1));
    expect(onLaunch).toHaveBeenCalledWith('powershell.exe', [...(preset?.args ?? [])]);
  });

  it('sends no argument for a preset without arguments', async () => {
    const { onLaunch } = renderModal();
    fireEvent.click(screen.getByRole('button', { name: 'cmd.exe' }));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('app.launcher.modal.submit') }));

    await waitFor(() => expect(onLaunch).toHaveBeenCalledTimes(1));
    expect(onLaunch).toHaveBeenCalledWith('cmd.exe', []);
  });
});
