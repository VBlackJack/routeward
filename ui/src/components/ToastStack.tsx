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

import React from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, CheckCircle2, X } from 'lucide-react';
import { ToastNotification } from '../types/routeward';

interface ToastStackProps {
  toasts: ToastNotification[];
  onDismiss: (id: string) => void;
}

export const ToastStack: React.FC<ToastStackProps> = ({ toasts, onDismiss }) => {
  const { t } = useTranslation();

  if (toasts.length === 0) {
    return null;
  }

  return (
    <div className="fixed bottom-12 right-6 z-50 flex flex-col gap-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          role={toast.severity === 'error' ? 'alert' : 'status'}
          className={`tf-card flex items-center gap-2.5 border-l-4 px-4 py-2.5 text-xs font-medium text-tf-primary shadow-xl ${
            toast.severity === 'error'
              ? 'border-l-tf-red'
              : 'border-l-tf-accent'
          }`}
        >
          {toast.severity === 'error' ? (
            <AlertTriangle className="h-4 w-4 text-tf-red" />
          ) : (
            <CheckCircle2 className="h-4 w-4 text-tf-accent" />
          )}
          <span>{toast.message}</span>
          {toast.actionLabel && toast.onAction && (
            <button
              type="button"
              onClick={() => {
                toast.onAction?.();
                onDismiss(toast.id);
              }}
              className="ml-1 rounded-tf-sm bg-tf-accent/20 px-2 py-0.5 text-[11px] font-bold text-tf-accent transition hover:bg-tf-accent/30"
            >
              {toast.actionLabel}
            </button>
          )}
          {toast.severity === 'error' && (
            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              aria-label={t('app.toast.dismiss')}
              className="ml-1 rounded-tf-sm p-0.5 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      ))}
    </div>
  );
};
