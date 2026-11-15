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

import React, { useEffect, useRef } from 'react';

interface ModalContainerProps {
  labelledBy?: string;
  onClose: () => void;
  alignTop?: boolean;
  backdropClassName?: string;
  children: React.ReactNode;
}

/**
 * Shared accessible modal wrapper that handles ARIA dialog semantics, Escape
 * key closing, backdrop click closing, initial focus, and focus restoration.
 */
export const ModalContainer: React.FC<ModalContainerProps> = ({
  labelledBy,
  onClose,
  alignTop = false,
  backdropClassName = 'bg-black/70 p-4 backdrop-blur-sm',
  children
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const onCloseRef = useRef(onClose);

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const node = containerRef.current;
    if (node) {
      const focusTarget = node.querySelector<HTMLElement>(
        'input:not([type="hidden"]):not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
      if (focusTarget) {
        focusTarget.focus();
      } else {
        node.focus();
      }
    }

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onCloseRef.current();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      if (previouslyFocused && typeof previouslyFocused.focus === 'function') {
        previouslyFocused.focus();
      }
    };
  }, []);

  return (
    <div
      className={`fixed inset-0 z-50 flex ${
        alignTop ? 'items-start pt-20' : 'items-center'
      } justify-center ${backdropClassName}`}
      onClick={() => onCloseRef.current()}
    >
      <div
        ref={containerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        tabIndex={-1}
        className="contents"
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </div>
    </div>
  );
};
