# Copyright 2026 Julien Bombled
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Runtime check of packaging/linux/routeward.service: systemd as PID 1 in a container, the real
# .deb installed. Build from the repository root:
#   docker build -f tests/linux/systemd/Dockerfile -t routeward-systemd-test .
# Drive it with tests/linux/systemd/run-systemd-checks.sh (needs --privileged and the host cgroup).

FROM rust:1.97.1-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends dpkg-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . /workspace

# A Windows checkout may carry CRLF line endings: the packaging scripts and the unit must be LF.
RUN sed -i 's/\r$//' packaging/linux/* \
    && cargo build --release -p routeward-cli \
    && bash packaging/linux/build-deb.sh --target-dir /workspace/target/release --out-dir /out

FROM debian:bookworm

ENV container=docker
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus \
    nftables iproute2 curl python3 procps ca-certificates kmod \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /lib/systemd/system/multi-user.target.wants/* \
        /etc/systemd/system/*.wants/* \
        /lib/systemd/system/local-fs.target.wants/* \
        /lib/systemd/system/sockets.target.wants/*udev* \
        /lib/systemd/system/sockets.target.wants/*initctl* \
        /lib/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup* \
        /lib/systemd/system/systemd-update-utmp*

COPY --from=builder /out/ /opt/routeward-deb/
# dpkg -i: the dependencies (nftables, iproute2) are installed above.
RUN dpkg -i /opt/routeward-deb/routeward_*.deb

# rwctl: member of group routeward (IPC socket client). rwtest: unprivileged user that runs curl.
RUN useradd --create-home --shell /bin/bash rwtest \
    && useradd --create-home --shell /bin/bash --groups routeward rwctl

COPY tests/linux/mock_servers.py /opt/routeward-test/mock_servers.py
COPY tests/linux/systemd/run-systemd-checks.sh /opt/routeward-test/run-systemd-checks.sh
RUN sed -i 's/\r$//' /opt/routeward-test/mock_servers.py /opt/routeward-test/run-systemd-checks.sh \
    && chmod +x /opt/routeward-test/mock_servers.py /opt/routeward-test/run-systemd-checks.sh \
    && systemctl mask getty.target console-getty.service systemd-logind.service

STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
