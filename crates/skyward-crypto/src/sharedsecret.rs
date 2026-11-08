//! Agreeing with the secure world on the key it signs its notes with. A
//! note the credential service writes is what the key service wants before
//! it will use a key a screen lock guards, and the two recognise each
//! other's notes only by a key they agree on first. Each part of the secure
//! world that keeps keys offers a seed and a number used once; every part
//! is told all of them, and each works out the same key from them. Android
//! has its key service do this as the phone starts, before anything asks
//! for a note.

// The calls and answers serve the phone's own driver and the host tests.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use anyhow::{Context, Result};
use skyward_binder::parcel::{Parcel, Reader};
use skyward_binder::status;

/// What a part of the secure world that keeps keys registers as, where it
/// agrees on such a key at all.
pub const INTERFACE: &str = "android.hardware.security.sharedsecret.ISharedSecret";

const GET_PARAMETERS: u32 = 1;
const COMPUTE: u32 = 2;

/// What one part of the secure world brings to the agreement.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Parameters {
    /// What it keeps across starts, the same every time.
    pub seed: Vec<u8>,
    /// What it draws afresh at each start.
    pub nonce: Vec<u8>,
}

/// What one part of the secure world answered when asked what it brings.
fn parameters(read: &mut Reader) -> Result<Parameters> {
    status::ok(read).context("ask what the secure world brings to the agreement")?;
    let end = read
        .structure()
        .context("read what the secure world brings")?;
    let seed = read
        .blob()
        .context("read the seed the secure world keeps")?;
    let nonce = read
        .blob()
        .context("read the number the secure world drew")?;
    read.go(end)?;
    Ok(Parameters { seed, nonce })
}

/// The call that tells a part of the secure world what every part brought,
/// so it can work out the key from all of them.
fn ask_compute(all: &[Parameters]) -> Parcel {
    let mut call = Parcel::call(INTERFACE);
    call.i32(all.len() as i32);
    for p in all {
        // Each is a structure of its own: that it is there, how long it is,
        // then its fields.
        call.i32(1);
        let at = call.here();
        call.i32(0);
        call.blob(&p.seed);
        call.blob(&p.nonce);
        let size = (call.here() - at) as i32;
        call.fill(at, size);
    }
    call
}

/// What came back from working out the key: what each part answers so the
/// parts can be told apart from one another, which is the same everywhere
/// the agreement held.
fn agreed(read: &mut Reader) -> Result<Vec<u8>> {
    status::ok(read).context("have the secure world work out the key it signs its notes with")?;
    read.blob()
        .context("read what the secure world answered about the key")
}

/// A part of the secure world that keeps keys, as this program talks to it.
#[cfg(target_os = "android")]
pub struct SharedSecret<'a> {
    device: skyward_binder::driver::Handle<'a>,
}

#[cfg(target_os = "android")]
impl<'a> SharedSecret<'a> {
    /// Reach the part registered under `name`, or say that none is.
    pub fn open(
        binder: &'a skyward_binder::driver::Binder,
        name: &str,
    ) -> Result<SharedSecret<'a>> {
        let device = skyward_binder::service::find(binder, name)?.with_context(|| {
            format!("{name} is not running; the phone's key service has to be started first")
        })?;
        Ok(SharedSecret { device })
    }

    pub fn parameters(&self) -> Result<Parameters> {
        let reply = self
            .device
            .transact(GET_PARAMETERS, &Parcel::call(INTERFACE))
            .context("ask what the secure world brings to the agreement")?;
        parameters(&mut reply.read())
    }

    pub fn compute(&self, all: &[Parameters]) -> Result<Vec<u8>> {
        let reply = self
            .device
            .transact(COMPUTE, &ask_compute(all))
            .context("have the secure world work out the key it signs its notes with")?;
        agreed(&mut reply.read())
    }
}

/// Have every part of the secure world named in `names` agree on the key
/// they sign their notes with, as Android's key service has them agree as
/// the phone starts: each is asked what it brings, and then every one of
/// them is told what all of them brought. They are told it in one order,
/// the order the values sort in, since each works the key out from the
/// values in the order it is given them. Returns how many agreed.
#[cfg(target_os = "android")]
pub fn agree(binder: &skyward_binder::driver::Binder, names: &[String]) -> Result<usize> {
    let parts: Vec<SharedSecret> = names
        .iter()
        .map(|n| SharedSecret::open(binder, n))
        .collect::<Result<_>>()?;
    let mut all: Vec<Parameters> = parts
        .iter()
        .map(|p| p.parameters())
        .collect::<Result<_>>()?;
    all.sort();
    let mut agreed = None;
    for (part, name) in parts.iter().zip(names) {
        let said = part
            .compute(&all)
            .with_context(|| format!("have {name} work out the key it signs its notes with"))?;
        anyhow::ensure!(
            agreed.get_or_insert_with(|| said.clone()) == &said,
            "{name} worked out another key than the rest of the secure world"
        );
    }
    Ok(parts.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply that went through, carrying one structure.
    fn answered(fields: impl FnOnce(&mut Parcel)) -> Vec<u8> {
        let mut p = Parcel::default();
        p.i32(0);
        p.i32(1);
        let at = p.here();
        p.i32(0);
        fields(&mut p);
        let size = (p.here() - at) as i32;
        p.fill(at, size);
        p.bytes().to_vec()
    }

    #[test]
    fn a_part_brings_a_seed_it_keeps_and_a_number_it_drew() {
        let reply = answered(|p| {
            p.blob(&[1; 32]);
            p.blob(&[2; 32]);
        });
        let brought = parameters(&mut Reader::new(&reply)).unwrap();
        assert_eq!(
            brought,
            Parameters {
                seed: vec![1; 32],
                nonce: vec![2; 32]
            }
        );
    }

    #[test]
    fn working_out_the_key_tells_the_secure_world_what_every_part_brought() {
        let all = [
            Parameters {
                seed: vec![],
                nonce: vec![9; 32],
            },
            Parameters {
                seed: vec![4; 32],
                nonce: vec![5; 32],
            },
        ];
        let call = ask_compute(&all);
        let mut r = Reader::new(call.bytes());
        for _ in 0..3 {
            r.i32().unwrap();
        }
        assert_eq!(r.string().unwrap(), INTERFACE);
        assert_eq!(r.i32().unwrap(), 2, "both parts are named");
        for p in &all {
            let end = r.structure().unwrap();
            assert_eq!(r.blob().unwrap(), p.seed);
            assert_eq!(r.blob().unwrap(), p.nonce);
            r.go(end).unwrap();
        }
        assert_eq!(r.here(), call.bytes().len());
    }

    #[test]
    fn the_values_are_given_in_the_order_they_sort_in() {
        let mut all = vec![
            Parameters {
                seed: vec![2],
                nonce: vec![1],
            },
            Parameters {
                seed: vec![1],
                nonce: vec![9],
            },
            Parameters {
                seed: vec![1],
                nonce: vec![3],
            },
        ];
        all.sort();
        assert_eq!(
            all,
            [
                Parameters {
                    seed: vec![1],
                    nonce: vec![3]
                },
                Parameters {
                    seed: vec![1],
                    nonce: vec![9]
                },
                Parameters {
                    seed: vec![2],
                    nonce: vec![1]
                },
            ]
        );
    }

    #[test]
    fn what_came_back_is_what_tells_the_parts_apart() {
        let mut p = Parcel::default();
        p.i32(0);
        p.blob(&[0xAB; 32]);
        assert_eq!(agreed(&mut Reader::new(p.bytes())).unwrap(), vec![0xAB; 32]);
    }
}
