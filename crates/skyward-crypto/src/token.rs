//! The note the phone's secure world writes once a user has answered their
//! screen lock. The part that checks the credential hands the note out and
//! the part that holds the keys accepts it, both inside the secure world, so
//! what it says is fixed between them and cannot be forged outside: it
//! carries a signature only they can make.

use anyhow::{bail, Result};

/// The only layout written so far.
const LATEST: u8 = 0;

/// Where each field starts. Every one is packed against the next, so the
/// note is no longer than its fields.
const CHALLENGE: usize = 1;
const USER: usize = 9;
const AUTHENTICATOR: usize = 17;
const KIND: usize = 25;
const WHEN: usize = 29;
const MAC: usize = 37;

/// How long its signature is, and so how long the note is.
const MAC_BYTES: usize = 32;
const BYTES: usize = MAC + MAC_BYTES;

/// The note itself, read out into the fields the key service is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// What the note was asked for, where something asked for one.
    pub challenge: i64,
    /// Which of the secure world's own users answered. This is the number
    /// a key is bound to, and has nothing to do with the user numbers the
    /// rest of the phone counts in.
    pub user: i64,
    /// Which enrolment of that user's credential answered.
    pub authenticator: i64,
    /// What the user answered with: a credential, or a fingerprint or face.
    pub kind: i32,
    /// When the secure world wrote the note, by its own clock.
    pub when: i64,
    /// The signature the rest of the secure world checks.
    pub mac: Vec<u8>,
}

impl Token {
    /// Read a note the secure world wrote. It chose this machine's own
    /// order for the numbers that are only passed along, and the order the
    /// network uses for the two it compares, which is how both ends of a
    /// phone agree on them whatever they are built for.
    pub fn of(raw: &[u8]) -> Result<Token> {
        if raw.len() != BYTES {
            bail!(
                "the secure world's note is {} bytes, and {BYTES} is the length of one",
                raw.len()
            );
        }
        if raw[0] != LATEST {
            bail!("the secure world's note is written in layout {}, and Skyward reads layout {LATEST}", raw[0]);
        }
        let own = |at: usize| i64::from_le_bytes(raw[at..at + 8].try_into().expect("eight bytes"));
        Ok(Token {
            challenge: own(CHALLENGE),
            user: own(USER),
            authenticator: own(AUTHENTICATOR),
            kind: i32::from_be_bytes(raw[KIND..KIND + 4].try_into().expect("four bytes")),
            when: i64::from_be_bytes(raw[WHEN..WHEN + 8].try_into().expect("eight bytes")),
            mac: raw[MAC..].to_vec(),
        })
    }

    /// The note as the key service is given it: the same bytes it came in
    /// as, which is what the hardware checks the signature over.
    pub fn bytes(&self) -> Vec<u8> {
        let mut raw = vec![LATEST];
        raw.extend_from_slice(&self.challenge.to_le_bytes());
        raw.extend_from_slice(&self.user.to_le_bytes());
        raw.extend_from_slice(&self.authenticator.to_le_bytes());
        raw.extend_from_slice(&self.kind.to_be_bytes());
        raw.extend_from_slice(&self.when.to_be_bytes());
        raw.extend_from_slice(&self.mac);
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note() -> Vec<u8> {
        let mut raw = vec![LATEST];
        raw.extend_from_slice(&7i64.to_le_bytes());
        raw.extend_from_slice(&0x253c_22c3_acbb_a741u64.to_le_bytes());
        raw.extend_from_slice(&9i64.to_le_bytes());
        raw.extend_from_slice(&1i32.to_be_bytes());
        raw.extend_from_slice(&1_700_000_000i64.to_be_bytes());
        raw.extend_from_slice(&[0xAB; MAC_BYTES]);
        raw
    }

    #[test]
    fn the_note_is_read_out_field_by_field() {
        let raw = note();
        assert_eq!(raw.len(), BYTES);
        let token = Token::of(&raw).unwrap();
        assert_eq!(token.challenge, 7);
        assert_eq!(
            token.user as u64, 0x253c_22c3_acbb_a741,
            "the secure world's own user, as it wrote it"
        );
        assert_eq!(token.authenticator, 9);
        assert_eq!(token.kind, 1);
        assert_eq!(
            token.when, 1_700_000_000,
            "the time, in the order the network uses"
        );
        assert_eq!(token.mac, vec![0xAB; MAC_BYTES]);
    }

    #[test]
    fn a_note_of_the_wrong_length_or_layout_is_an_error() {
        assert!(Token::of(&note()[..BYTES - 1]).is_err());
        assert!(Token::of(&[]).is_err());
        let mut later = note();
        later[0] = 1;
        assert!(Token::of(&later).is_err());
    }
}
