use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use hmac::digest::KeyInit as HmacKeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const MAX_CRYPTO_REASSEMBLY: usize = 64 * 1024;
const MAX_CRYPTO_RANGES: usize = 32;
const MAX_ACK_RANGES: usize = 32;

const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_V1_DRAFT_INITIAL_SALT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];
const QUIC_V2_INITIAL_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicClientHello {
    pub server_name: Option<String>,
    pub alpns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicProbeResult {
    Found(QuicClientHello),
    Incomplete,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicCryptoFragment {
    pub data: Vec<u8>,
    pub ranges: Vec<(usize, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicProbeFragmentResult {
    Found(QuicClientHello),
    Incomplete(QuicCryptoFragment),
    None,
}

struct LongHeader<'a> {
    version: u32,
    dcid: &'a [u8],
    pn_offset: usize,
    payload_offset: usize,
    payload_len: usize,
}

pub fn probe_quic_client_hello(packet: &[u8]) -> Option<QuicClientHello> {
    match probe_quic_client_hello_result(packet) {
        QuicProbeResult::Found(client_hello) => Some(client_hello),
        QuicProbeResult::Incomplete | QuicProbeResult::None => None,
    }
}

pub fn probe_quic_client_hello_result(packet: &[u8]) -> QuicProbeResult {
    match probe_quic_client_hello_fragment_result(packet) {
        QuicProbeFragmentResult::Found(client_hello) => QuicProbeResult::Found(client_hello),
        QuicProbeFragmentResult::Incomplete(_) => QuicProbeResult::Incomplete,
        QuicProbeFragmentResult::None => QuicProbeResult::None,
    }
}

pub fn probe_quic_client_hello_fragment_result(packet: &[u8]) -> QuicProbeFragmentResult {
    let mut packet_offset = 0;
    let mut combined_data = Vec::new();
    let mut combined_ranges = Vec::new();
    while packet_offset < packet.len() {
        let Some(header) = parse_initial_long_header_at(packet, packet_offset) else {
            break;
        };
        let Some(packet_end) = packet_end(&header) else {
            break;
        };
        if packet.len() < packet_end {
            break;
        }
        let salts = salts_for_version(header.version);
        for salt in salts {
            match decrypt_and_parse(packet, &header, salt) {
                DecryptResult::Found(result) => return QuicProbeFragmentResult::Found(result),
                DecryptResult::Incomplete(fragment) => {
                    merge_crypto_fragment(&mut combined_data, &mut combined_ranges, fragment);
                    if let Some(client_hello) =
                        parse_tls_client_hello_from_crypto(&combined_data, &combined_ranges)
                    {
                        return QuicProbeFragmentResult::Found(client_hello);
                    }
                    break;
                }
                DecryptResult::None => {}
            }
        }
        packet_offset = packet_end;
    }
    if combined_data.is_empty() {
        QuicProbeFragmentResult::None
    } else {
        QuicProbeFragmentResult::Incomplete(QuicCryptoFragment {
            data: combined_data,
            ranges: combined_ranges,
        })
    }
}

fn salts_for_version(version: u32) -> &'static [&'static [u8; 20]] {
    match version {
        0x0000_0001 => &[&QUIC_V1_INITIAL_SALT],
        0x6b33_43cf => &[&QUIC_V2_INITIAL_SALT],
        0xff00_001d..=0xff00_0020 => &[&QUIC_V1_DRAFT_INITIAL_SALT],
        _ => &[
            &QUIC_V1_INITIAL_SALT,
            &QUIC_V1_DRAFT_INITIAL_SALT,
            &QUIC_V2_INITIAL_SALT,
        ],
    }
}

fn parse_initial_long_header_at(packet: &[u8], start: usize) -> Option<LongHeader<'_>> {
    if packet.len().saturating_sub(start) < 7 || packet[start] & 0x80 == 0 {
        return None;
    }
    let packet_type = (packet[start] & 0x30) >> 4;
    if packet_type != 0 {
        return None;
    }
    let version = u32::from_be_bytes(packet.get(start + 1..start + 5)?.try_into().ok()?);
    let mut offset = start + 5;
    let dcid_len = *packet.get(offset)? as usize;
    offset += 1;
    let dcid = packet.get(offset..offset + dcid_len)?;
    offset += dcid_len;
    let scid_len = *packet.get(offset)? as usize;
    offset += 1 + scid_len;
    read_varint(packet, &mut offset)?;
    let payload_len = read_varint(packet, &mut offset)? as usize;
    let pn_offset = offset;
    if packet.len() < pn_offset + 4 {
        return None;
    }
    Some(LongHeader {
        version,
        dcid,
        pn_offset,
        payload_offset: pn_offset,
        payload_len,
    })
}

fn packet_end(header: &LongHeader<'_>) -> Option<usize> {
    header.pn_offset.checked_add(header.payload_len)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DecryptResult {
    Found(QuicClientHello),
    Incomplete(QuicCryptoFragment),
    None,
}

fn decrypt_and_parse(packet: &[u8], header: &LongHeader<'_>, salt: &[u8; 20]) -> DecryptResult {
    let Some(packet_end) = packet_end(header) else {
        return DecryptResult::None;
    };
    let Some(packet) = packet.get(..packet_end) else {
        return DecryptResult::None;
    };
    let mut protected = packet.to_vec();
    let Some((key, iv, hp)) = derive_initial_keys(header.dcid, salt) else {
        return DecryptResult::None;
    };
    if remove_header_protection(&mut protected, header.pn_offset, &hp).is_none() {
        return DecryptResult::None;
    }
    let pn_len = (protected[0] & 0x03) as usize + 1;
    let Some(pn_bytes) = protected.get(header.pn_offset..header.pn_offset + pn_len) else {
        return DecryptResult::None;
    };
    let packet_number = pn_bytes
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | *byte as u64);
    let payload_offset = header.payload_offset + pn_len;
    let Some(header_bytes) = protected.get(..payload_offset).map(|value| value.to_vec()) else {
        return DecryptResult::None;
    };
    let Some(payload) = protected.get_mut(payload_offset..) else {
        return DecryptResult::None;
    };
    if payload.len() < 16 {
        return DecryptResult::None;
    }
    let payload_len = payload.len();
    let tag = Tag::clone_from_slice(&payload[payload_len - 16..]);
    let ciphertext = &mut payload[..payload_len - 16];
    let nonce = packet_nonce(&iv, packet_number);
    let Ok(cipher) = Aes128Gcm::new_from_slice(&key) else {
        return DecryptResult::None;
    };
    if cipher
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), &header_bytes, ciphertext, &tag)
        .is_err()
    {
        return DecryptResult::None;
    }
    match extract_crypto_stream(ciphertext) {
        CryptoExtract::Complete(crypto) => parse_tls_client_hello(&crypto)
            .map(DecryptResult::Found)
            .unwrap_or(DecryptResult::None),
        CryptoExtract::Incomplete(fragment) => DecryptResult::Incomplete(fragment),
        CryptoExtract::None => DecryptResult::None,
    }
}

fn derive_initial_keys(dcid: &[u8], salt: &[u8; 20]) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    let initial_secret = hkdf_extract(salt, dcid)?;
    let client_secret = hkdf_expand_label(&initial_secret, b"client in", &[], 32)?;
    let key = hkdf_expand_label(&client_secret, b"quic key", &[], 16)?
        .try_into()
        .ok()?;
    let iv = hkdf_expand_label(&client_secret, b"quic iv", &[], 12)?
        .try_into()
        .ok()?;
    let hp = hkdf_expand_label(&client_secret, b"quic hp", &[], 16)?
        .try_into()
        .ok()?;
    Some((key, iv, hp))
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Option<[u8; 32]> {
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(salt).ok()?;
    mac.update(ikm);
    Some(mac.finalize().into_bytes().into())
}

fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Option<Vec<u8>> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, len)
}

fn hkdf_expand(secret: &[u8], info: &[u8], len: usize) -> Option<Vec<u8>> {
    let mut okm = Vec::with_capacity(len);
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(secret).ok()?;
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&previous);
        counter = counter.checked_add(1)?;
    }
    okm.truncate(len);
    Some(okm)
}

fn remove_header_protection(packet: &mut [u8], pn_offset: usize, hp_key: &[u8; 16]) -> Option<()> {
    let sample = packet.get(pn_offset + 4..pn_offset + 20)?;
    let cipher = Aes128::new(GenericArray::from_slice(hp_key));
    let mut block = GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut block);
    packet[0] ^= block[0] & 0x0f;
    let pn_len = (packet[0] & 0x03) as usize + 1;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= block[i + 1];
    }
    Some(())
}

fn packet_nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for (idx, byte) in packet_number.to_be_bytes().iter().enumerate() {
        nonce[4 + idx] ^= *byte;
    }
    nonce
}

enum CryptoExtract {
    Complete(Vec<u8>),
    Incomplete(QuicCryptoFragment),
    None,
}

fn extract_crypto_stream(payload: &[u8]) -> CryptoExtract {
    let mut offset = 0;
    let mut out = Vec::new();
    let mut ranges = Vec::new();
    while offset < payload.len() {
        let Some(frame_type) = read_varint(payload, &mut offset) else {
            return incomplete_crypto(out, ranges);
        };
        match frame_type {
            0x00 | 0x01 => {}
            0x02 => {
                if skip_ack_frame(payload, &mut offset, false).is_none() {
                    return incomplete_crypto(out, ranges);
                }
            }
            0x03 => {
                if skip_ack_frame(payload, &mut offset, true).is_none() {
                    return incomplete_crypto(out, ranges);
                }
            }
            0x06 => {
                let Some(crypto_offset) =
                    read_varint(payload, &mut offset).map(|value| value as usize)
                else {
                    return incomplete_crypto(out, ranges);
                };
                let Some(len) = read_varint(payload, &mut offset).map(|value| value as usize)
                else {
                    return incomplete_crypto(out, ranges);
                };
                let Some(frame_end) = crypto_offset.checked_add(len) else {
                    return CryptoExtract::None;
                };
                if frame_end > MAX_CRYPTO_REASSEMBLY || ranges.len() >= MAX_CRYPTO_RANGES {
                    return CryptoExtract::None;
                }
                let Some(data) = payload.get(offset..offset + len) else {
                    return incomplete_crypto(out, ranges);
                };
                offset += len;
                if out.len() < frame_end {
                    out.resize(frame_end, 0);
                }
                out[crypto_offset..frame_end].copy_from_slice(data);
                ranges.push((crypto_offset, frame_end));
            }
            0x1c | 0x1d => break,
            _ => break,
        }
    }
    if out.is_empty() {
        CryptoExtract::None
    } else if tls_client_hello_is_complete(&out) && ranges_cover(&ranges, 0, out.len()) {
        CryptoExtract::Complete(out)
    } else {
        incomplete_crypto(out, ranges)
    }
}

fn skip_ack_frame(data: &[u8], offset: &mut usize, has_ecn_counts: bool) -> Option<()> {
    read_varint(data, offset)?;
    read_varint(data, offset)?;
    let ack_range_count = read_varint(data, offset)? as usize;
    if ack_range_count > MAX_ACK_RANGES {
        return None;
    }
    read_varint(data, offset)?;
    for _ in 0..ack_range_count {
        read_varint(data, offset)?;
        read_varint(data, offset)?;
    }
    if has_ecn_counts {
        read_varint(data, offset)?;
        read_varint(data, offset)?;
        read_varint(data, offset)?;
    }
    Some(())
}

fn incomplete_crypto(data: Vec<u8>, ranges: Vec<(usize, usize)>) -> CryptoExtract {
    if data.is_empty() || ranges.is_empty() {
        CryptoExtract::None
    } else {
        CryptoExtract::Incomplete(QuicCryptoFragment { data, ranges })
    }
}

fn merge_crypto_fragment(
    data: &mut Vec<u8>,
    ranges: &mut Vec<(usize, usize)>,
    fragment: QuicCryptoFragment,
) {
    if data.len() < fragment.data.len() {
        data.resize(fragment.data.len(), 0);
    }
    for (start, end) in fragment.ranges {
        if let Some(fragment_data) = fragment.data.get(start..end) {
            data[start..end].copy_from_slice(fragment_data);
            ranges.push((start, end));
        }
    }
}

fn ranges_cover(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    let mut ranges = ranges.to_vec();
    ranges.sort_unstable_by_key(|(range_start, _)| *range_start);
    let mut covered = start;
    for (range_start, range_end) in ranges {
        if range_start > covered {
            return false;
        }
        if range_end > covered {
            covered = range_end;
            if covered >= end {
                return true;
            }
        }
    }
    covered >= end
}

fn tls_client_hello_is_complete(data: &[u8]) -> bool {
    if data.first().copied() != Some(0x01) || data.len() < 4 {
        return false;
    }
    let Some(msg_len) = read_u24(&data[1..4]).map(|value| value as usize) else {
        return false;
    };
    data.len() >= 4 + msg_len
}

pub fn parse_tls_client_hello_from_crypto(
    data: &[u8],
    ranges: &[(usize, usize)],
) -> Option<QuicClientHello> {
    if data.first().copied() != Some(0x01) || data.len() < 4 {
        return None;
    }
    let msg_len = read_u24(data.get(1..4)?)? as usize;
    let end = 4 + msg_len;
    if data.len() < end || !ranges_cover(ranges, 0, end) {
        return None;
    }
    parse_tls_client_hello(data.get(..end)?)
}

fn parse_tls_client_hello(data: &[u8]) -> Option<QuicClientHello> {
    if *data.first()? != 0x01 {
        return None;
    }
    let msg_len = read_u24(data.get(1..4)?)? as usize;
    let mut offset = 4;
    let end = offset + msg_len;
    data.get(offset..end)?;
    offset += 2 + 32;
    let session_len = *data.get(offset)? as usize;
    offset += 1 + session_len;
    let cipher_len = u16::from_be_bytes(data.get(offset..offset + 2)?.try_into().ok()?) as usize;
    offset += 2 + cipher_len;
    let compression_len = *data.get(offset)? as usize;
    offset += 1 + compression_len;
    let ext_len = u16::from_be_bytes(data.get(offset..offset + 2)?.try_into().ok()?) as usize;
    offset += 2;
    let ext_end = offset + ext_len;
    data.get(offset..ext_end)?;

    let mut server_name = None;
    let mut alpns = Vec::new();
    while offset + 4 <= ext_end {
        let ext_type = u16::from_be_bytes(data.get(offset..offset + 2)?.try_into().ok()?);
        let ext_data_len =
            u16::from_be_bytes(data.get(offset + 2..offset + 4)?.try_into().ok()?) as usize;
        offset += 4;
        let ext_data = data.get(offset..offset + ext_data_len)?;
        offset += ext_data_len;
        match ext_type {
            0x0000 => server_name = parse_sni_extension(ext_data).or(server_name),
            0x0010 => alpns = parse_alpn_extension(ext_data),
            _ => {}
        }
    }

    Some(QuicClientHello { server_name, alpns })
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    let list_len = u16::from_be_bytes(data.get(0..2)?.try_into().ok()?) as usize;
    let mut offset = 2;
    let end = offset + list_len;
    data.get(offset..end)?;
    while offset + 3 <= end {
        let name_type = *data.get(offset)?;
        let name_len =
            u16::from_be_bytes(data.get(offset + 1..offset + 3)?.try_into().ok()?) as usize;
        offset += 3;
        let name = data.get(offset..offset + name_len)?;
        offset += name_len;
        if name_type == 0 {
            return std::str::from_utf8(name)
                .ok()
                .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
                .filter(|name| !name.is_empty());
        }
    }
    None
}

fn parse_alpn_extension(data: &[u8]) -> Vec<String> {
    let Some(list_len) = data
        .get(0..2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
    else {
        return Vec::new();
    };
    let mut offset = 2;
    let end = offset + list_len;
    if data.get(offset..end).is_none() {
        return Vec::new();
    }
    let mut result = Vec::new();
    while offset < end {
        let Some(len) = data.get(offset).copied().map(usize::from) else {
            break;
        };
        offset += 1;
        let Some(protocol) = data.get(offset..offset + len) else {
            break;
        };
        offset += len;
        if let Ok(protocol) = std::str::from_utf8(protocol) {
            result.push(protocol.to_string());
        }
    }
    result
}

fn read_varint(data: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *data.get(*offset)?;
    let len = 1usize << (first >> 6);
    let bytes = data.get(*offset..*offset + len)?;
    let mut value = (first & 0x3f) as u64;
    for byte in &bytes[1..] {
        value = (value << 8) | *byte as u64;
    }
    *offset += len;
    Some(value)
}

fn read_u24(data: &[u8]) -> Option<u32> {
    Some(((*data.first()? as u32) << 16) | ((*data.get(1)? as u32) << 8) | *data.get(2)? as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello_message() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);

        let mut extensions = Vec::new();
        let hostname = b"qq.com";
        let mut sni = Vec::new();
        sni.extend_from_slice(&(hostname.len() as u16 + 3).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni.extend_from_slice(hostname);
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);

        let mut alpn = Vec::new();
        alpn.extend_from_slice(&3u16.to_be_bytes());
        alpn.push(2);
        alpn.extend_from_slice(b"h3");
        extensions.extend_from_slice(&0x10u16.to_be_bytes());
        extensions.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&alpn);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut message = vec![0x01];
        message.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        message.extend_from_slice(&body);

        message
    }

    #[test]
    fn parses_tls_client_hello_sni_and_alpn() {
        let message = client_hello_message();
        let parsed = parse_tls_client_hello(&message).expect("client hello should parse");
        assert_eq!(parsed.server_name.as_deref(), Some("qq.com"));
        assert_eq!(parsed.alpns, vec!["h3"]);
    }

    #[test]
    fn waits_until_crypto_ranges_cover_full_client_hello() {
        let message = client_hello_message();
        let split = message.len() / 2;
        let mut partial = vec![0; message.len()];
        partial[..split].copy_from_slice(&message[..split]);
        assert!(parse_tls_client_hello_from_crypto(&partial, &[(0, split)]).is_none());

        partial[split..].copy_from_slice(&message[split..]);
        let parsed =
            parse_tls_client_hello_from_crypto(&partial, &[(split, message.len()), (0, split)])
                .expect("merged client hello should parse");
        assert_eq!(parsed.server_name.as_deref(), Some("qq.com"));
        assert_eq!(parsed.alpns, vec!["h3"]);
    }

    #[test]
    fn merges_crypto_fragments_from_coalesced_initials() {
        let message = client_hello_message();
        let split = message.len() / 2;
        let mut data = Vec::new();
        let mut ranges = Vec::new();
        merge_crypto_fragment(
            &mut data,
            &mut ranges,
            QuicCryptoFragment {
                data: message[..split].to_vec(),
                ranges: vec![(0, split)],
            },
        );
        assert!(parse_tls_client_hello_from_crypto(&data, &ranges).is_none());

        merge_crypto_fragment(
            &mut data,
            &mut ranges,
            QuicCryptoFragment {
                data: message.clone(),
                ranges: vec![(split, message.len())],
            },
        );
        let parsed = parse_tls_client_hello_from_crypto(&data, &ranges)
            .expect("coalesced fragments should parse");
        assert_eq!(parsed.server_name.as_deref(), Some("qq.com"));
        assert_eq!(parsed.alpns, vec!["h3"]);
    }
}
