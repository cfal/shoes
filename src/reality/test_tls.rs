//! Independent target-wire fixtures for REALITY admission and mirroring tests.

use super::reality_key_exchange::RealityGroup;

pub(super) fn construct_server_hello(
    random: &[u8; 32],
    session: &[u8],
    cipher: u16,
    group: RealityGroup,
    key_share: &[u8],
) -> std::io::Result<Vec<u8>> {
    if key_share.len() != group.share_len(false) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid server key share size",
        ));
    }
    let mut hello = vec![2, 0, 0, 0, 3, 3];
    hello.extend_from_slice(random);
    hello.push(session.len() as u8);
    hello.extend_from_slice(session);
    hello.extend_from_slice(&cipher.to_be_bytes());
    hello.push(0);

    let mut extensions = vec![0, 43, 0, 2, 3, 4];
    extensions.extend_from_slice(&[0, 51]);
    extensions.extend_from_slice(&((4 + key_share.len()) as u16).to_be_bytes());
    extensions.extend_from_slice(&(group as u16).to_be_bytes());
    extensions.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
    extensions.extend_from_slice(key_share);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let length = (hello.len() - 4) as u32;
    hello[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
    Ok(hello)
}

pub(super) fn write_record_header(record_type: u8, length: u16) -> Vec<u8> {
    let mut header = vec![record_type, 3, 3];
    header.extend_from_slice(&length.to_be_bytes());
    header
}
