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

FROM rust:1.97.1-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    dnsmasq-base \
    iproute2 \
    curl \
    python3 \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy

# Dedicated unprivileged account that runs the DNS server of the Fake-IP exemption scenario.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin rwdns

WORKDIR /workspace
COPY . /workspace

RUN sed -i 's/\r$//' /workspace/tests/linux/run-scenarios.sh /workspace/tests/linux/mock_servers.py \
    && chmod +x /workspace/tests/linux/run-scenarios.sh /workspace/tests/linux/mock_servers.py

RUN cargo fmt --check \
    && cargo clippy -p routeward-core -p routeward-cli --all-targets -- -D warnings \
    && cargo test -p routeward-core -p routeward-cli \
    && cargo build --release -p routeward-cli \
    && cargo build --release -p routeward-core --example socks5_udp_test_server

CMD ["/workspace/tests/linux/run-scenarios.sh"]
