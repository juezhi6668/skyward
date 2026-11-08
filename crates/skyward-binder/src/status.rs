use crate::parcel::Reader;
use anyhow::{Context, Result};
use std::fmt;

const NONE: i32 = 0;
const SECURITY: i32 = -1;
const BAD_PARCELABLE: i32 = -2;
const ILLEGAL_ARGUMENT: i32 = -3;
const NULL_POINTER: i32 = -4;
const ILLEGAL_STATE: i32 = -5;
const UNSUPPORTED_OPERATION: i32 = -7;
const SERVICE_SPECIFIC: i32 = -8;
const TRANSACTION_FAILED: i32 = -129;

/// Why a call did not go through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// The service turned the call down in its own terms, by its own number.
    Service { code: i32, said: String },
    /// The call did not reach the method at all.
    Call { exception: i32, said: String },
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::Service { code, said } => write!(
                f,
                "the service refused the call with its error {code}{}",
                aside(said)
            ),
            Fault::Call { exception, said } => {
                write!(f, "the call ended in {}{}", name(*exception), aside(said))
            }
        }
    }
}

impl std::error::Error for Fault {}

fn name(exception: i32) -> &'static str {
    match exception {
        SECURITY => "a refusal on security grounds",
        BAD_PARCELABLE => "a value it could not read",
        ILLEGAL_ARGUMENT => "an argument it would not take",
        NULL_POINTER => "an argument that was missing",
        ILLEGAL_STATE => "a state it was not ready for",
        UNSUPPORTED_OPERATION => "something it does not do",
        TRANSACTION_FAILED => "a failure in the driver",
        _ => "a failure",
    }
}

fn aside(said: &str) -> String {
    if said.is_empty() {
        String::new()
    } else {
        format!(" ({said})")
    }
}

/// Read the mark every reply opens with, leaving the reader on whatever the
/// method itself answered. What a refusal carries is a message, room for a
/// trace the service did not send, and, when the service has its own
/// numbering, its number.
pub fn ok(r: &mut Reader) -> Result<()> {
    let exception = r.i32().context("read how the call ended")?;
    if exception == NONE {
        return Ok(());
    }
    let said = r.string().unwrap_or_default();
    r.i32().context("read the room left for a trace")?;
    Err(match exception {
        SERVICE_SPECIFIC => Fault::Service {
            code: r.i32().context("read the service's own error")?,
            said,
        },
        _ => Fault::Call { exception, said },
    }
    .into())
}

/// The service's own error number, when that is why a call failed.
pub fn refused_with(e: &anyhow::Error) -> Option<i32> {
    match e.downcast_ref::<Fault>() {
        Some(Fault::Service { code, .. }) => Some(*code),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parcel::Parcel;

    fn refusal(exception: i32, said: &str, code: i32) -> Vec<u8> {
        let mut p = Parcel::default();
        p.i32(exception);
        p.string(said);
        p.i32(0);
        p.i32(code);
        p.bytes().to_vec()
    }

    #[test]
    fn a_reply_that_went_through_leaves_the_rest_to_be_read() {
        let mut p = Parcel::default();
        p.i32(NONE);
        p.i32(1234);
        let bytes = p.bytes().to_vec();
        let mut r = Reader::new(&bytes);
        ok(&mut r).unwrap();
        assert_eq!(r.i32().unwrap(), 1234);
    }

    #[test]
    fn a_services_own_error_number_can_be_acted_on() {
        let bytes = refusal(SERVICE_SPECIFIC, "no such key", -62);
        let e = ok(&mut Reader::new(&bytes)).unwrap_err();
        assert_eq!(refused_with(&e), Some(-62));
        let said = format!("{e:#}");
        assert!(
            said.contains("-62") && said.contains("no such key"),
            "{said}"
        );
    }

    #[test]
    fn a_services_error_is_still_found_under_what_the_caller_added() {
        let bytes = refusal(SERVICE_SPECIFIC, "", -43);
        let e = ok(&mut Reader::new(&bytes))
            .unwrap_err()
            .context("unwrap the key");
        assert_eq!(refused_with(&e), Some(-43));
    }

    #[test]
    fn a_refusal_by_the_binder_layer_is_named_and_is_not_the_services_own() {
        let bytes = refusal(SECURITY, "", 0);
        let e = ok(&mut Reader::new(&bytes)).unwrap_err();
        assert_eq!(refused_with(&e), None);
        assert!(format!("{e:#}").contains("security"), "{e:#}");
    }
}
