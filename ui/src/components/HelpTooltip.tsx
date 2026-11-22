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
import { HelpCircle } from 'lucide-react';

interface HelpTooltipProps {
  text: string;
}

export const HelpTooltip: React.FC<HelpTooltipProps> = ({ text }) => {
  const [open, setOpen] = useState(false);
  // A click pins the tooltip so that hovering first and then clicking does not close it.
  const [pinned, setPinned] = useState(false);
  const tooltipId = useId();

  const close = () => {
    setOpen(false);
    setPinned(false);
  };

  return (
    <span
      className="relative inline-flex items-center"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => {
        if (!pinned) {
          setOpen(false);
        }
      }}
    >
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          if (pinned) {
            close();
          } else {
            setOpen(true);
            setPinned(true);
          }
        }}
        onFocus={() => setOpen(true)}
        onBlur={close}
        onKeyDown={(e) => {
          if (e.key === 'Escape' && open) {
            // Close only the tooltip, not the surrounding modal.
            e.stopPropagation();
            close();
          }
        }}
        className="inline-flex h-6 w-6 items-center justify-center rounded-full text-tf-secondary transition hover:bg-tf-surface-alt hover:text-tf-accent"
        aria-label={text}
        aria-expanded={open}
        aria-describedby={open ? tooltipId : undefined}
      >
        <HelpCircle className="h-3.5 w-3.5" />
      </button>
      {open && (
        <span
          id={tooltipId}
          role="tooltip"
          className="absolute bottom-full left-1/2 z-50 mb-2 w-64 -translate-x-1/2 rounded-tf-md border border-tf-accent/50 bg-tf-surface p-2.5 text-[11px] font-normal leading-relaxed text-tf-primary shadow-xl"
        >
          {text}
        </span>
      )}
    </span>
  );
};
