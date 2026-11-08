use anyhow::{bail, Context, Result};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::time::Duration;

/// Where init says which descriptor holds the socket it made for the
/// recovery service.
const SOCKET_ENV: &str = "ANDROID_SOCKET_recovery";

/// How long a program that connected has to send its byte.
const READ_TIMEOUT: Duration = Duration::from_secs(1);

/// What a program asks of the recovery over its socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// adbd, for `adb reboot fastboot`.
    Fastboot,
    /// fastbootd, for `fastboot reboot recovery`.
    Recovery,
}

impl Request {
    fn parse(byte: u8) -> Result<Request> {
        Ok(match byte {
            b'f' => Request::Fastboot,
            b'r' => Request::Recovery,
            _ => bail!("the recovery socket got {byte:#04x}, which asks for nothing"),
        })
    }
}

/// The socket init makes for the recovery service: adbd and fastbootd each
/// connect and write one byte, to have the recovery go over to fastboot or
/// come back from it.
pub struct Control {
    listener: UnixListener,
}

impl Control {
    /// The socket init handed this process, listening; none when the
    /// process was not started by init as the recovery service.
    pub fn open() -> Result<Option<Control>> {
        let Ok(var) = std::env::var(SOCKET_ENV) else {
            return Ok(None);
        };
        let fd: RawFd = var
            .parse()
            .with_context(|| format!("{SOCKET_ENV} is {var:?}"))?;
        // init binds the socket and leaves the listening to the service; the
        // phone's own programs the recovery starts are not to inherit it.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
            || unsafe { libc::listen(fd, 4) } < 0
        {
            return Err(io::Error::last_os_error()).context("listen on the recovery socket");
        }
        Control::over(unsafe { UnixListener::from_raw_fd(fd) }).map(Some)
    }

    fn over(listener: UnixListener) -> Result<Control> {
        listener
            .set_nonblocking(true)
            .context("stop the recovery socket from blocking")?;
        Ok(Control { listener })
    }

    /// What to wait on for a program to connect.
    pub fn fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    /// The requests waiting, in the order the programs connected.
    pub fn requests(&self) -> Result<Vec<Request>> {
        let mut out = Vec::new();
        loop {
            let mut stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(out),
                Err(e) => return Err(e).context("accept on the recovery socket"),
            };
            // Some systems hand on the listener's non-blocking mode.
            stream
                .set_nonblocking(false)
                .context("let the recovery socket's connection block")?;
            let mut ready = libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            match unsafe { libc::poll(&mut ready, 1, READ_TIMEOUT.as_millis() as i32) } {
                n if n < 0 => {
                    return Err(io::Error::last_os_error())
                        .context("wait on the recovery socket's connection")
                }
                0 => bail!(
                    "a program connected to the recovery socket and sent nothing for {} ms",
                    READ_TIMEOUT.as_millis()
                ),
                _ => {}
            }
            let mut byte = [0u8; 1];
            stream
                .read_exact(&mut byte)
                .context("read what was asked on the recovery socket")?;
            out.push(Request::parse(byte[0])?);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    fn socket(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("skyward-{name}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn each_program_that_connects_asks_one_thing() {
        let path = socket("asks");
        let control = Control::over(UnixListener::bind(&path).unwrap()).unwrap();
        assert!(
            control.requests().unwrap().is_empty(),
            "no one has connected"
        );
        for byte in *b"fr" {
            UnixStream::connect(&path)
                .unwrap()
                .write_all(&[byte])
                .unwrap();
        }
        assert_eq!(
            control.requests().unwrap(),
            vec![Request::Fastboot, Request::Recovery]
        );
        assert!(control.requests().unwrap().is_empty(), "each is taken once");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_byte_that_asks_for_nothing_is_an_error() {
        let path = socket("nothing");
        let control = Control::over(UnixListener::bind(&path).unwrap()).unwrap();
        UnixStream::connect(&path).unwrap().write_all(b"x").unwrap();
        assert!(control.requests().is_err());
        std::fs::remove_file(&path).unwrap();
    }
}
