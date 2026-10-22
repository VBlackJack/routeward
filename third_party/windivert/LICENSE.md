# WinDivert License and Source Attribution

## Upstream Project

- **Project**: WinDivert (Windows Packet Divert)
- **Version**: 2.2.2
- **Author**: Basil (`basil00`, reqrypt.org)
- **Official Source Repository**: https://github.com/basil00/WinDivert
- **Official Release Archive**: https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip
- **Pinned Archive SHA-256**: `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`

## Dual License Notice (LGPLv3 / GPLv2)

WinDivert is dual-licensed at the user's election under either:
1. **The GNU Lesser General Public License, Version 3 (LGPLv3)**, or
2. **The GNU General Public License, Version 2 (GPLv2)**.

RouteWard elects to use WinDivert under the terms of the **GNU Lesser General Public License, Version 3 (LGPLv3)**:
- RouteWard does **not** statically link WinDivert and does **not** commit WinDivert binary artifacts (`WinDivert.dll`, `WinDivert64.sys`, `WinDivert32.sys`) to the source repository.
- On Windows, `routeward-core` loads `WinDivert.dll` exclusively at runtime via dynamic linking (`LoadLibraryW` / `GetProcAddress`).
- Users are free to inspect, modify, recompile, or replace `WinDivert.dll` on disk with any interface-compatible version, in accordance with Section 4 of the GNU Lesser General Public License v3.

---

## WinDivert Official Copyright Notice

```text
WinDivert is dual-licensed under the GNU Lesser General Public License (LGPL)
Version 3, or the GNU General Public License (GPL) Version 2:

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
```

Full text of the GNU Lesser General Public License Version 3: https://www.gnu.org/licenses/lgpl-3.0.txt
