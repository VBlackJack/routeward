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

const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_EXT_SERVER_NAME: u16 = 0x0000;
const TLS_SNI_HOST_NAME_TYPE: u8 = 0x00;
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 4;
const TLS_CLIENT_RANDOM_LEN: usize = 32;

pub struct TlsSniExtractor;

impl TlsSniExtractor {
    /// Extracts the Server Name Indication (SNI) hostname from a TLS ClientHello packet.
    /// Returns `None` if the payload is not a valid TLS ClientHello or has no SNI extension.
    pub fn extract_sni(packet: &[u8]) -> Option<String> {
        if packet.len() < TLS_RECORD_HEADER_LEN + TLS_HANDSHAKE_HEADER_LEN {
            return None;
        }
        if packet[0] != TLS_RECORD_HANDSHAKE {
            return None;
        }

        let record_len = u16::from_be_bytes([packet[3], packet[4]]) as usize;
        let payload = packet.get(
            TLS_RECORD_HEADER_LEN
                ..TLS_RECORD_HEADER_LEN + record_len.min(packet.len() - TLS_RECORD_HEADER_LEN),
        )?;

        if payload.first().copied()? != TLS_HANDSHAKE_CLIENT_HELLO {
            return None;
        }

        // Skip HandshakeType (1) + Length (3) + ClientVersion (2) + Random (32)
        let mut cursor = TLS_HANDSHAKE_HEADER_LEN + 2 + TLS_CLIENT_RANDOM_LEN;
        if cursor >= payload.len() {
            return None;
        }

        // Session ID
        let session_id_len = *payload.get(cursor)? as usize;
        cursor += 1 + session_id_len;

        // Cipher Suites
        let cipher_suites_len =
            u16::from_be_bytes([*payload.get(cursor)?, *payload.get(cursor + 1)?]) as usize;
        cursor += 2 + cipher_suites_len;

        // Compression Methods
        let comp_methods_len = *payload.get(cursor)? as usize;
        cursor += 1 + comp_methods_len;

        // Extensions total length
        if cursor + 2 > payload.len() {
            return None;
        }
        let extensions_len =
            u16::from_be_bytes([*payload.get(cursor)?, *payload.get(cursor + 1)?]) as usize;
        cursor += 2;

        let extensions_end = (cursor + extensions_len).min(payload.len());
        while cursor + 4 <= extensions_end {
            let ext_type = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
            let ext_len = u16::from_be_bytes([payload[cursor + 2], payload[cursor + 3]]) as usize;
            cursor += 4;

            if cursor + ext_len > extensions_end {
                break;
            }

            if ext_type == TLS_EXT_SERVER_NAME && ext_len >= 5 {
                let sni_data = &payload[cursor..cursor + ext_len];
                let list_len = u16::from_be_bytes([sni_data[0], sni_data[1]]) as usize;
                let mut pos = 2;
                let list_end = (2 + list_len).min(sni_data.len());
                while pos + 3 <= list_end {
                    let name_type = sni_data[pos];
                    let name_len =
                        u16::from_be_bytes([sni_data[pos + 1], sni_data[pos + 2]]) as usize;
                    pos += 3;
                    if pos + name_len <= list_end && name_type == TLS_SNI_HOST_NAME_TYPE {
                        let host_bytes = &sni_data[pos..pos + name_len];
                        if let Ok(hostname) = std::str::from_utf8(host_bytes) {
                            return Some(hostname.to_lowercase());
                        }
                    }
                    pos += name_len;
                }
            }

            cursor += ext_len;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_hostname_from_tls_client_hello() {
        let host = b"stealth.torproject.org";
        let host_len = host.len() as u16;
        let sni_list_len = host_len + 3;
        let sni_ext_len = sni_list_len + 2;
        let extensions_total_len = sni_ext_len + 4;

        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 version
        hello_body.extend_from_slice(&[0u8; 32]); // Random
        hello_body.push(0); // Session ID len = 0
        hello_body.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites len = 2
        hello_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hello_body.push(1); // Compression methods len = 1
        hello_body.push(0); // null compression
        hello_body.extend_from_slice(&extensions_total_len.to_be_bytes());
        hello_body.extend_from_slice(&0u16.to_be_bytes()); // Extension: server_name (0)
        hello_body.extend_from_slice(&sni_ext_len.to_be_bytes());
        hello_body.extend_from_slice(&sni_list_len.to_be_bytes());
        hello_body.push(0); // host_name type
        hello_body.extend_from_slice(&host_len.to_be_bytes());
        hello_body.extend_from_slice(host);

        let handshake_len = hello_body.len() as u32;
        let mut handshake = vec![0x01]; // ClientHello
        handshake.extend_from_slice(&handshake_len.to_be_bytes()[1..4]);
        handshake.extend_from_slice(&hello_body);

        let record_len = handshake.len() as u16;
        let mut packet = vec![0x16, 0x03, 0x01];
        packet.extend_from_slice(&record_len.to_be_bytes());
        packet.extend_from_slice(&handshake);

        let extracted = TlsSniExtractor::extract_sni(&packet).expect("Extracted SNI hostname");
        assert_eq!(extracted, "stealth.torproject.org");
    }
}
