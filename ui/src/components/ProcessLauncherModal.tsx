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

import React, { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Play, Terminal, X } from 'lucide-react';
import { ModalContainer } from './ModalContainer';

interface ProcessLauncherModalProps {
  relayEndpoint: string;
  onLaunch: (executable: string, args: string[]) => Promise<void>;
  onClose: () => void;
}

const QUICK_LAUNCH_BINARIES = [
  { exe: 'curl.exe', args: 'https://api.ipify.org?format=json' },
  { exe: 'powershell.exe', args: '-NoExit' },
  { exe: 'cmd.exe', args: '' }
];

export const ProcessLauncherModal: React.FC<ProcessLauncherModalProps> = ({
  relayEndpoint,
  onLaunch,
  onClose
}) => {
  const { t } = useTranslation();
  const titleId = useId();
  const exeInputId = useId();
  const argsInputId = useId();
  const [executable, setExecutable] = useState('curl.exe');
  const [rawArgs, setRawArgs] = useState('https://api.ipify.org?format=json');
  const [launching, setLaunching] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!executable.trim()) return;
    setLaunching(true);
    const parsedArgs = rawArgs
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    try {
      await onLaunch(executable.trim(), parsedArgs);
      onClose();
    } catch {
      // Toast error is raised by caller; keep modal open so user can adjust path/args
    } finally {
      setLaunching(false);
    }
  };

  return (
    <ModalContainer onClose={onClose} labelledBy={titleId}>
      <div className="tf-card w-full max-w-lg p-6 shadow-2xl">
        <div className="flex items-start justify-between border-b border-tf-border pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-tf-md bg-tf-accent/20 text-tf-accent">
              <Terminal className="h-5 w-5" />
            </div>
            <div>
              <h2 id={titleId} className="text-base font-bold text-tf-primary">
                {t('app.launcher.modal.title')}
              </h2>
              <p className="text-xs text-tf-secondary">
                {t('app.launcher.modal.subtitle')}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={t('app.launcher.modal.cancel')}
            className="rounded-tf-sm p-1 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="mt-4 space-y-4">
          <div className="flex flex-wrap gap-1.5">
            {QUICK_LAUNCH_BINARIES.map((preset) => (
              <button
                key={preset.exe}
                type="button"
                onClick={() => {
                  setExecutable(preset.exe);
                  setRawArgs(preset.args);
                }}
                className="tf-surface-alt px-2.5 py-1 font-mono text-[11px] text-tf-cyan hover:border-tf-accent"
              >
                {preset.exe}
              </button>
            ))}
          </div>

          <div>
            <label
              htmlFor={exeInputId}
              className="mb-1 block text-xs font-semibold text-tf-secondary"
            >
              {t('app.launcher.modal.executable_label')}
            </label>
            <input
              id={exeInputId}
              type="text"
              value={executable}
              onChange={(e) => setExecutable(e.target.value)}
              placeholder={t('app.launcher.modal.executable_placeholder')}
              className="tf-input w-full px-3 py-2 font-mono text-xs"
              required
            />
          </div>

          <div>
            <label
              htmlFor={argsInputId}
              className="mb-1 block text-xs font-semibold text-tf-secondary"
            >
              {t('app.launcher.modal.args_label')}
            </label>
            <input
              id={argsInputId}
              type="text"
              value={rawArgs}
              onChange={(e) => setRawArgs(e.target.value)}
              placeholder={t('app.launcher.modal.args_placeholder')}
              className="tf-input w-full px-3 py-2 font-mono text-xs"
            />
          </div>

          <div className="tf-surface-alt p-3 font-mono text-[11px] text-tf-secondary">
            <div>
              ALL_PROXY ={' '}
              <span className="text-tf-green">socks5h://{relayEndpoint}</span>
            </div>
            <div>
              HTTP_PROXY / HTTPS_PROXY ={' '}
              <span className="text-tf-cyan">http://{relayEndpoint}</span>
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="tf-surface-alt px-4 py-2 text-xs font-semibold text-tf-secondary hover:text-tf-primary"
            >
              {t('app.launcher.modal.cancel')}
            </button>
            <button
              type="submit"
              disabled={launching}
              className="tf-btn-accent flex items-center gap-2 px-4 py-2 text-xs"
            >
              <Play className="h-3.5 w-3.5" />
              {t('app.launcher.modal.submit')}
            </button>
          </div>
        </form>
      </div>
    </ModalContainer>
  );
};
