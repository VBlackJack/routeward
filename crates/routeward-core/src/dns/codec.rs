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

#![forbid(unsafe_code)]

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const DNS_HEADER_LEN: usize = 12;
pub const DNS_DEFAULT_UDP_MAX_BYTES: usize = 512;
pub const DNS_MAX_TCP_MESSAGE_BYTES: usize = 65535;
const MAX_DOMAIN_NAME_BYTES: usize = 255;
const MAX_LABEL_LEN: usize = 63;
const MAX_COMPRESSION_JUMPS: usize = 16;
const POINTER_MASK: u8 = 0xC0;

pub const QTYPE_A: u16 = 1;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_PTR: u16 = 12;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_OPT: u16 = 41;

pub const QCLASS_IN: u16 = 1;

pub const FLAG_QR_RESPONSE: u16 = 0x8000;
pub const FLAG_AA: u16 = 0x0400;
pub const FLAG_TC: u16 = 0x0200;
pub const FLAG_RD: u16 = 0x0100;
pub const FLAG_RA: u16 = 0x0080;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsCodecError {
    PacketTooShort,
    UnexpectedResponseBit,
    MissingQuestion,
    InvalidLabelLength,
    CompressionPointerOutOfBounds,
    CompressionPointerLoop,
    DomainNameTooLong,
    InvalidUtf8Label,
    TruncatedResourceRecord,
    InvalidRdataLength,
}

impl fmt::Display for DnsCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort => write!(f, "DNS packet shorter than 12-byte header"),
            Self::UnexpectedResponseBit => write!(f, "expected DNS query (QR=0), got response"),
            Self::MissingQuestion => write!(f, "DNS query has QDCOUNT=0"),
            Self::InvalidLabelLength => write!(f, "invalid DNS label length or prefix"),
            Self::CompressionPointerOutOfBounds => {
                write!(f, "DNS compression pointer points outside packet bounds")
            }
            Self::CompressionPointerLoop => {
                write!(f, "DNS compression pointer loop or excessive jumps")
            }
            Self::DomainNameTooLong => write!(f, "DNS domain name exceeds 255 bytes"),
            Self::InvalidUtf8Label => write!(f, "DNS label is not valid ASCII/UTF-8"),
            Self::TruncatedResourceRecord => write!(f, "truncated DNS resource record"),
            Self::InvalidRdataLength => write!(f, "invalid RDATA length for record type"),
        }
    }
}

impl std::error::Error for DnsCodecError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQueryPacket {
    pub id: u16,
    pub flags: u16,
    pub question: DnsQuestion,
    /// Raw bytes of the first question entry (`QNAME + QTYPE + QCLASS`) as received on the wire,
    /// or re-encoded when constructed synthetically.
    pub raw_question_section: Vec<u8>,
    /// Maximum UDP payload size advertised by the client (default 512, or EDNS0 OPT UDP payload size).
    pub max_udp_payload_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRdata {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    Cname(String),
    Ptr(String),
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: DnsRdata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub authorities: Vec<DnsResourceRecord>,
    pub additionals: Vec<DnsResourceRecord>,
}

impl DnsMessage {
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }

    pub fn is_truncated(&self) -> bool {
        (self.flags & FLAG_TC) != 0
    }
}

/// Decodes a domain name starting at `start_offset` in `packet`, supporting RFC 1035 label compression
/// (`0xC0`) with strict bounds checking and a maximum jump count to prevent pointer loops.
/// Returns `(normalized_domain, offset_immediately_after_name)`.
pub fn decode_domain_name(
    packet: &[u8],
    start_offset: usize,
) -> Result<(String, usize), DnsCodecError> {
    if start_offset >= packet.len() {
        return Err(DnsCodecError::PacketTooShort);
    }

    let mut labels: Vec<String> = Vec::new();
    let mut pos = start_offset;
    let mut end_offset: Option<usize> = None;
    let mut jumps = 0usize;
    let mut total_bytes = 0usize;

    loop {
        let Some(&len_byte) = packet.get(pos) else {
            return Err(DnsCodecError::PacketTooShort);
        };

        if len_byte == 0 {
            if end_offset.is_none() {
                end_offset = Some(pos + 1);
            }
            break;
        }

        if (len_byte & POINTER_MASK) == POINTER_MASK {
            let Some(&second_byte) = packet.get(pos + 1) else {
                return Err(DnsCodecError::PacketTooShort);
            };
            if end_offset.is_none() {
                end_offset = Some(pos + 2);
            }
            jumps += 1;
            if jumps > MAX_COMPRESSION_JUMPS {
                return Err(DnsCodecError::CompressionPointerLoop);
            }
            let ptr_target = (((len_byte & 0x3F) as usize) << 8) | (second_byte as usize);
            if ptr_target >= packet.len() || ptr_target == pos {
                return Err(DnsCodecError::CompressionPointerOutOfBounds);
            }
            pos = ptr_target;
            continue;
        }

        if (len_byte & POINTER_MASK) != 0 {
            return Err(DnsCodecError::InvalidLabelLength);
        }

        let label_len = len_byte as usize;
        if label_len > MAX_LABEL_LEN {
            return Err(DnsCodecError::InvalidLabelLength);
        }
        let label_start = pos + 1;
        let label_end = label_start.saturating_add(label_len);
        let Some(label_slice) = packet.get(label_start..label_end) else {
            return Err(DnsCodecError::PacketTooShort);
        };

        total_bytes = total_bytes.saturating_add(label_len + 1);
        if total_bytes > MAX_DOMAIN_NAME_BYTES {
            return Err(DnsCodecError::DomainNameTooLong);
        }

        let label_str =
            std::str::from_utf8(label_slice).map_err(|_| DnsCodecError::InvalidUtf8Label)?;
        labels.push(label_str.to_ascii_lowercase());
        pos = label_end;
    }

    let final_offset = end_offset.unwrap_or(pos);
    Ok((labels.join("."), final_offset))
}

/// Encodes a dotted domain name into RFC 1035 uncompressed label format ending with `0x00`.
pub fn encode_domain_name(domain: &str, out: &mut Vec<u8>) -> Result<(), DnsCodecError> {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        out.push(0);
        return Ok(());
    }

    let mut total_written = 0usize;
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_LABEL_LEN {
            return Err(DnsCodecError::InvalidLabelLength);
        }
        total_written = total_written.saturating_add(1 + bytes.len());
        if total_written + 1 > MAX_DOMAIN_NAME_BYTES {
            return Err(DnsCodecError::DomainNameTooLong);
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    Ok(())
}

/// Parses an incoming DNS query packet (`QR == 0`), extracting the first question and any EDNS0
/// UDP payload size from the Additional section.
pub fn parse_dns_query(packet: &[u8]) -> Result<DnsQueryPacket, DnsCodecError> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(DnsCodecError::PacketTooShort);
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & FLAG_QR_RESPONSE) != 0 {
        return Err(DnsCodecError::UnexpectedResponseBit);
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let nscount = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let arcount = u16::from_be_bytes([packet[10], packet[11]]) as usize;

    if qdcount == 0 {
        return Err(DnsCodecError::MissingQuestion);
    }

    let (qname, after_name) = decode_domain_name(packet, DNS_HEADER_LEN)?;
    let Some(q_tail) = packet.get(after_name..after_name + 4) else {
        return Err(DnsCodecError::PacketTooShort);
    };
    let qtype = u16::from_be_bytes([q_tail[0], q_tail[1]]);
    let qclass = u16::from_be_bytes([q_tail[2], q_tail[3]]);
    let first_question_end = after_name + 4;

    let mut raw_question_section = Vec::new();
    if encode_domain_name(&qname, &mut raw_question_section).is_ok() {
        raw_question_section.extend_from_slice(&qtype.to_be_bytes());
        raw_question_section.extend_from_slice(&qclass.to_be_bytes());
    } else if let Some(raw_slice) = packet.get(DNS_HEADER_LEN..first_question_end) {
        raw_question_section.extend_from_slice(raw_slice);
    }

    // Attempt to inspect Additional records for an EDNS0 OPT record (type 41) to learn client max UDP size.
    let mut max_udp_payload_bytes = DNS_DEFAULT_UDP_MAX_BYTES;
    let mut cursor = first_question_end;
    let mut parse_ok = true;

    for _ in 1..qdcount {
        if let Ok((_, next_name)) = decode_domain_name(packet, cursor) {
            if next_name + 4 <= packet.len() {
                cursor = next_name + 4;
            } else {
                parse_ok = false;
                break;
            }
        } else {
            parse_ok = false;
            break;
        }
    }

    if parse_ok {
        for _ in 0..(ancount + nscount) {
            if let Ok((_, next_pos)) = skip_resource_record(packet, cursor) {
                cursor = next_pos;
            } else {
                parse_ok = false;
                break;
            }
        }
    }

    if parse_ok {
        for _ in 0..arcount {
            if let Ok((rtype, rclass, next_pos)) = skip_resource_record_header(packet, cursor) {
                if rtype == QTYPE_OPT {
                    let advertised = rclass as usize;
                    if advertised > max_udp_payload_bytes {
                        max_udp_payload_bytes = advertised.min(4096);
                    }
                }
                cursor = next_pos;
            } else {
                break;
            }
        }
    }

    Ok(DnsQueryPacket {
        id,
        flags,
        question: DnsQuestion {
            qname,
            qtype,
            qclass,
        },
        raw_question_section,
        max_udp_payload_bytes,
    })
}

fn skip_resource_record(packet: &[u8], offset: usize) -> Result<(u16, usize), DnsCodecError> {
    let (rtype, _, next) = skip_resource_record_header(packet, offset)?;
    Ok((rtype, next))
}

fn skip_resource_record_header(
    packet: &[u8],
    offset: usize,
) -> Result<(u16, u16, usize), DnsCodecError> {
    let (_, after_name) = decode_domain_name(packet, offset)?;
    let Some(hdr) = packet.get(after_name..after_name + 10) else {
        return Err(DnsCodecError::TruncatedResourceRecord);
    };
    let rtype = u16::from_be_bytes([hdr[0], hdr[1]]);
    let rclass = u16::from_be_bytes([hdr[2], hdr[3]]);
    let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]) as usize;
    let rdata_end = (after_name + 10).saturating_add(rdlen);
    if rdata_end > packet.len() {
        return Err(DnsCodecError::TruncatedResourceRecord);
    }
    Ok((rtype, rclass, rdata_end))
}

/// Parses a full DNS wire message (query or response), including all Question, Answer,
/// Authority, and Additional resource records.
pub fn parse_dns_message(packet: &[u8]) -> Result<DnsMessage, DnsCodecError> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(DnsCodecError::PacketTooShort);
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let nscount = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let arcount = u16::from_be_bytes([packet[10], packet[11]]) as usize;

    let mut cursor = DNS_HEADER_LEN;
    let mut questions = Vec::with_capacity(qdcount.min(16));
    for _ in 0..qdcount {
        let (qname, after_name) = decode_domain_name(packet, cursor)?;
        let Some(tail) = packet.get(after_name..after_name + 4) else {
            return Err(DnsCodecError::PacketTooShort);
        };
        let qtype = u16::from_be_bytes([tail[0], tail[1]]);
        let qclass = u16::from_be_bytes([tail[2], tail[3]]);
        questions.push(DnsQuestion {
            qname,
            qtype,
            qclass,
        });
        cursor = after_name + 4;
    }

    let mut answers = Vec::with_capacity(ancount.min(32));
    for _ in 0..ancount {
        let (rr, next) = parse_resource_record(packet, cursor)?;
        answers.push(rr);
        cursor = next;
    }

    let mut authorities = Vec::with_capacity(nscount.min(16));
    for _ in 0..nscount {
        let (rr, next) = parse_resource_record(packet, cursor)?;
        authorities.push(rr);
        cursor = next;
    }

    let mut additionals = Vec::with_capacity(arcount.min(16));
    for _ in 0..arcount {
        let (rr, next) = parse_resource_record(packet, cursor)?;
        additionals.push(rr);
        cursor = next;
    }

    Ok(DnsMessage {
        id,
        flags,
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn parse_resource_record(
    packet: &[u8],
    offset: usize,
) -> Result<(DnsResourceRecord, usize), DnsCodecError> {
    let (name, after_name) = decode_domain_name(packet, offset)?;
    let Some(hdr) = packet.get(after_name..after_name + 10) else {
        return Err(DnsCodecError::TruncatedResourceRecord);
    };
    let rtype = u16::from_be_bytes([hdr[0], hdr[1]]);
    let rclass = u16::from_be_bytes([hdr[2], hdr[3]]);
    let ttl = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]) as usize;

    let rdata_start = after_name + 10;
    let rdata_end = rdata_start.saturating_add(rdlen);
    let Some(rdata_slice) = packet.get(rdata_start..rdata_end) else {
        return Err(DnsCodecError::TruncatedResourceRecord);
    };

    let rdata = match rtype {
        QTYPE_A => {
            if rdata_slice.len() != 4 {
                return Err(DnsCodecError::InvalidRdataLength);
            }
            DnsRdata::A(Ipv4Addr::new(
                rdata_slice[0],
                rdata_slice[1],
                rdata_slice[2],
                rdata_slice[3],
            ))
        }
        QTYPE_AAAA => {
            if rdata_slice.len() != 16 {
                return Err(DnsCodecError::InvalidRdataLength);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata_slice);
            DnsRdata::AAAA(Ipv6Addr::from(octets))
        }
        QTYPE_CNAME => {
            let (cname, _) = decode_domain_name(packet, rdata_start)?;
            DnsRdata::Cname(cname)
        }
        QTYPE_PTR => {
            let (ptr_name, _) = decode_domain_name(packet, rdata_start)?;
            DnsRdata::Ptr(ptr_name)
        }
        _ => DnsRdata::Raw(rdata_slice.to_vec()),
    };

    Ok((
        DnsResourceRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        },
        rdata_end,
    ))
}

/// Builds a standard DNS query wire message (`RD = 1`, `QDCOUNT = 1`) for `domain` and `qtype`.
pub fn build_query(id: u16, domain: &str, qtype: u16) -> Result<Vec<u8>, DnsCodecError> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&FLAG_RD.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    encode_domain_name(domain, &mut pkt)?;
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
    Ok(pkt)
}

/// Builds a standard DNS `A` query wire message (`RD = 1`, `QDCOUNT = 1`) for `domain`.
pub fn build_a_query(id: u16, domain: &str) -> Result<Vec<u8>, DnsCodecError> {
    build_query(id, domain, QTYPE_A)
}

fn response_flags_for_query(query_flags: u16, rcode: u8) -> u16 {
    let rd = query_flags & FLAG_RD;
    let opcode = query_flags & 0x7800;
    FLAG_QR_RESPONSE | opcode | rd | FLAG_RA | ((rcode as u16) & 0x000F)
}

/// Builds a synthetic `A` response (`NOERROR`, `ANCOUNT = 1`) pointing to `ipv4` with `ttl_secs`.
pub fn build_a_response(query: &DnsQueryPacket, ipv4: Ipv4Addr, ttl_secs: u32) -> Vec<u8> {
    let flags = response_flags_for_query(query.flags, RCODE_NOERROR);
    let mut pkt = Vec::with_capacity(DNS_HEADER_LEN + query.raw_question_section.len() + 16);
    pkt.extend_from_slice(&query.id.to_be_bytes());
    pkt.extend_from_slice(&flags.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    pkt.extend_from_slice(&query.raw_question_section);

    // Answer RR using RFC 1035 compression pointer 0xC00C to the question QNAME at byte 12
    pkt.extend_from_slice(&[0xC0, 0x0C]);
    pkt.extend_from_slice(&QTYPE_A.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
    pkt.extend_from_slice(&ttl_secs.to_be_bytes());
    pkt.extend_from_slice(&4u16.to_be_bytes());
    pkt.extend_from_slice(&ipv4.octets());
    pkt
}

/// Builds a synthetic `AAAA` response (`NOERROR`, `ANCOUNT = 1`) pointing to `ipv6` with `ttl_secs`.
pub fn build_aaaa_response(query: &DnsQueryPacket, ipv6: Ipv6Addr, ttl_secs: u32) -> Vec<u8> {
    let flags = response_flags_for_query(query.flags, RCODE_NOERROR);
    let mut pkt = Vec::with_capacity(DNS_HEADER_LEN + query.raw_question_section.len() + 28);
    pkt.extend_from_slice(&query.id.to_be_bytes());
    pkt.extend_from_slice(&flags.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    pkt.extend_from_slice(&query.raw_question_section);

    pkt.extend_from_slice(&[0xC0, 0x0C]);
    pkt.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
    pkt.extend_from_slice(&ttl_secs.to_be_bytes());
    pkt.extend_from_slice(&16u16.to_be_bytes());
    pkt.extend_from_slice(&ipv6.octets());
    pkt
}

/// Builds a `PTR` response (`NOERROR`, `ANCOUNT = 1`) returning `ptrdname` with `ttl_secs`.
pub fn build_ptr_response(
    query: &DnsQueryPacket,
    ptrdname: &str,
    ttl_secs: u32,
) -> Result<Vec<u8>, DnsCodecError> {
    let mut encoded_target = Vec::with_capacity(ptrdname.len() + 2);
    encode_domain_name(ptrdname, &mut encoded_target)?;

    let flags = response_flags_for_query(query.flags, RCODE_NOERROR);
    let mut pkt = Vec::with_capacity(
        DNS_HEADER_LEN + query.raw_question_section.len() + 12 + encoded_target.len(),
    );
    pkt.extend_from_slice(&query.id.to_be_bytes());
    pkt.extend_from_slice(&flags.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    pkt.extend_from_slice(&query.raw_question_section);

    pkt.extend_from_slice(&[0xC0, 0x0C]);
    pkt.extend_from_slice(&QTYPE_PTR.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
    pkt.extend_from_slice(&ttl_secs.to_be_bytes());
    pkt.extend_from_slice(&(encoded_target.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&encoded_target);
    Ok(pkt)
}

/// Builds a `NODATA` response (`RCODE = 0 NOERROR`, `ANCOUNT = 0`).
pub fn build_nodata_response(query: &DnsQueryPacket) -> Vec<u8> {
    build_rcode_response(query, RCODE_NOERROR)
}

/// Builds an empty DNS response with the specified `rcode` (`NXDOMAIN = 3`, `SERVFAIL = 2`, etc.).
pub fn build_rcode_response(query: &DnsQueryPacket, rcode: u8) -> Vec<u8> {
    let flags = response_flags_for_query(query.flags, rcode);
    let mut pkt = Vec::with_capacity(DNS_HEADER_LEN + query.raw_question_section.len());
    pkt.extend_from_slice(&query.id.to_be_bytes());
    pkt.extend_from_slice(&flags.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    pkt.extend_from_slice(&query.raw_question_section);
    pkt
}

/// Builds a fallback RCODE response (`FORMERR` or `SERVFAIL`) from a raw buffer when full query parsing fails.
/// Returns `None` if the buffer is shorter than the 12-byte DNS header.
pub fn build_rcode_response_from_raw(raw_query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if raw_query.len() < DNS_HEADER_LEN {
        return None;
    }
    if let Ok(parsed) = parse_dns_query(raw_query) {
        return Some(build_rcode_response(&parsed, rcode));
    }
    let id = u16::from_be_bytes([raw_query[0], raw_query[1]]);
    let q_flags = u16::from_be_bytes([raw_query[2], raw_query[3]]);
    let flags = response_flags_for_query(q_flags, rcode);
    let mut pkt = Vec::with_capacity(DNS_HEADER_LEN);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&flags.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    Some(pkt)
}

/// Enforces UDP payload size limits on an outgoing DNS response. If `response_wire.len() > max_udp_bytes`,
/// returns a valid truncated DNS response with `TC = 1` (`0x0200`) and `ANCOUNT = NSCOUNT = ARCOUNT = 0`
/// so the stub resolver retries over TCP 53.
pub fn enforce_udp_truncation(
    response_wire: &[u8],
    query: &DnsQueryPacket,
    max_udp_bytes: usize,
) -> Vec<u8> {
    let limit = max_udp_bytes.max(DNS_DEFAULT_UDP_MAX_BYTES);
    if response_wire.len() <= limit {
        return response_wire.to_vec();
    }

    let orig_rcode = if response_wire.len() >= 4 {
        response_wire[3] & 0x0F
    } else {
        RCODE_NOERROR
    };
    let flags = response_flags_for_query(query.flags, orig_rcode) | FLAG_TC;
    let mut pkt = Vec::with_capacity(DNS_HEADER_LEN + query.raw_question_section.len());
    pkt.extend_from_slice(&query.id.to_be_bytes());
    pkt.extend_from_slice(&flags.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    pkt.extend_from_slice(&query.raw_question_section);
    pkt
}

/// Extracts all IPv4 addresses (`A` records) from the Answer section of a DNS response wire buffer.
pub fn extract_ipv4_answers(response_wire: &[u8]) -> Result<Vec<Ipv4Addr>, DnsCodecError> {
    let msg = parse_dns_message(response_wire)?;
    if msg.rcode() != RCODE_NOERROR {
        return Ok(Vec::new());
    }
    let mut addrs = Vec::new();
    for rr in msg.answers {
        if let DnsRdata::A(ip) = rr.rdata {
            addrs.push(ip);
        }
    }
    Ok(addrs)
}

/// Rewrites the 16-bit transaction ID at bytes `0..2` of a DNS message in place.
pub fn rewrite_transaction_id(wire: &mut [u8], id: u16) {
    if wire.len() >= 2 {
        let bytes = id.to_be_bytes();
        wire[0] = bytes[0];
        wire[1] = bytes[1];
    }
}

/// Prefixes a DNS wire message with its 2-byte big-endian length for DNS-over-TCP (RFC 1035 section 4.2.2).
pub fn encode_tcp_dns_frame(wire: &[u8]) -> Vec<u8> {
    let len = wire.len().min(DNS_MAX_TCP_MESSAGE_BYTES) as u16;
    let mut framed = Vec::with_capacity(2 + len as usize);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&wire[..len as usize]);
    framed
}

/// Parses a reverse `in-addr.arpa` query name (e.g. `"1.0.18.198.in-addr.arpa"`) into an `Ipv4Addr` (`198.18.0.1`).
pub fn parse_ipv4_ptr_qname(qname: &str) -> Option<Ipv4Addr> {
    let normalized = qname.trim().trim_end_matches('.').to_ascii_lowercase();
    let prefix = normalized.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<&str> = prefix.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let d = parts[0].parse::<u8>().ok()?;
    let c = parts[1].parse::<u8>().ok()?;
    let b = parts[2].parse::<u8>().ok()?;
    let a = parts[3].parse::<u8>().ok()?;
    Some(Ipv4Addr::new(a, b, c, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_parses_a_aaaa_ptr_and_cname_records_with_compression() {
        let query_bytes = build_a_query(0x1234, "Api.GitHub.com.").expect("valid A query");
        let parsed_q = parse_dns_query(&query_bytes).expect("parse query");
        assert_eq!(parsed_q.id, 0x1234);
        assert_eq!(parsed_q.question.qname, "api.github.com");
        assert_eq!(parsed_q.question.qtype, QTYPE_A);
        assert_eq!(parsed_q.question.qclass, QCLASS_IN);

        // Build A response with TTL = 5s
        let resp_a = build_a_response(&parsed_q, Ipv4Addr::new(198, 18, 0, 1), 5);
        let msg_a = parse_dns_message(&resp_a).expect("parse A response");
        assert_eq!(msg_a.id, 0x1234);
        assert_eq!(msg_a.rcode(), RCODE_NOERROR);
        assert_eq!(msg_a.answers.len(), 1);
        assert_eq!(msg_a.answers[0].name, "api.github.com");
        assert_eq!(msg_a.answers[0].ttl, 5);
        assert_eq!(
            msg_a.answers[0].rdata,
            DnsRdata::A(Ipv4Addr::new(198, 18, 0, 1))
        );
        assert_eq!(
            extract_ipv4_answers(&resp_a).expect("extract IPv4"),
            vec![Ipv4Addr::new(198, 18, 0, 1)]
        );

        // Build AAAA response and NODATA response
        let v6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let resp_aaaa = build_aaaa_response(&parsed_q, v6, 5);
        let msg_aaaa = parse_dns_message(&resp_aaaa).expect("parse AAAA response");
        assert_eq!(msg_aaaa.answers.len(), 1);
        assert_eq!(msg_aaaa.answers[0].rdata, DnsRdata::AAAA(v6));

        let nodata = build_nodata_response(&parsed_q);
        let msg_nodata = parse_dns_message(&nodata).expect("parse NODATA");
        assert_eq!(msg_nodata.rcode(), RCODE_NOERROR);
        assert!(msg_nodata.answers.is_empty());

        // PTR response and reverse IPv4 parser
        let ptr_ip =
            parse_ipv4_ptr_qname("1.0.18.198.in-addr.arpa").expect("valid reverse IPv4 qname");
        assert_eq!(ptr_ip, Ipv4Addr::new(198, 18, 0, 1));
        let ptr_resp =
            build_ptr_response(&parsed_q, "api.github.com", 5).expect("build PTR response");
        let msg_ptr = parse_dns_message(&ptr_resp).expect("parse PTR response");
        assert_eq!(
            msg_ptr.answers[0].rdata,
            DnsRdata::Ptr("api.github.com".to_string())
        );
    }

    #[test]
    fn rejects_compression_pointer_loops_and_malformed_packets_without_panic() {
        // 1. Self-referencing compression pointer at byte 12 (0xC0, 0x0C)
        let mut loop_pkt = vec![0u8; 18];
        loop_pkt[0] = 0xAA;
        loop_pkt[1] = 0xBB;
        loop_pkt[5] = 1; // QDCOUNT = 1
        loop_pkt[12] = 0xC0;
        loop_pkt[13] = 0x0C; // points to itself!
        assert!(parse_dns_query(&loop_pkt).is_err());

        // 2. Mutual compression pointer cycle: offset 12 -> offset 14 -> offset 12
        let mut cycle_pkt = vec![0u8; 20];
        cycle_pkt[5] = 1;
        cycle_pkt[12] = 0xC0;
        cycle_pkt[13] = 14;
        cycle_pkt[14] = 0xC0;
        cycle_pkt[15] = 12;
        assert_eq!(
            parse_dns_query(&cycle_pkt),
            Err(DnsCodecError::CompressionPointerLoop)
        );

        // 3. Out-of-bounds compression pointer
        let mut oob_pkt = vec![0u8; 18];
        oob_pkt[5] = 1;
        oob_pkt[12] = 0xC0;
        oob_pkt[13] = 0xFF;
        assert_eq!(
            parse_dns_query(&oob_pkt),
            Err(DnsCodecError::CompressionPointerOutOfBounds)
        );

        // 4. Truncated headers and truncated RRs never panic
        for len in 0..DNS_HEADER_LEN {
            assert_eq!(
                parse_dns_query(&vec![0u8; len]),
                Err(DnsCodecError::PacketTooShort)
            );
        }
        let mut trunc_rr = build_a_query(1, "example.com").unwrap();
        trunc_rr[2] = 0x81; // QR=1
        trunc_rr[7] = 1; // ANCOUNT=1, but no answer bytes follow
        assert!(parse_dns_message(&trunc_rr).is_err());
    }

    #[test]
    fn enforces_udp_truncation_flag_when_response_exceeds_512_bytes() {
        let query_bytes = build_a_query(0x7777, "large.example.com").expect("build query");
        let parsed_q = parse_dns_query(&query_bytes).expect("parse query");

        let mut oversized = build_a_response(&parsed_q, Ipv4Addr::new(93, 184, 216, 34), 60);
        oversized.resize(620, 0);

        let truncated = enforce_udp_truncation(&oversized, &parsed_q, 512);
        assert!(truncated.len() <= 512);
        let msg = parse_dns_message(&truncated).expect("parse truncated message");
        assert_eq!(msg.id, 0x7777);
        assert!(msg.is_truncated());
        assert_eq!(msg.questions.len(), 1);
        assert!(msg.answers.is_empty());
    }
}
