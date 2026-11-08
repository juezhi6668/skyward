//! Whether a network joined reaches the internet, told as the phone's own
//! system tells it: a page the phone maker keeps answers 204 and nothing
//! more, and a network that wants a login in a browser first answers in
//! its stead, most often sending on to its login page.

use crate::dns;
use anyhow::{anyhow, bail, ensure, Context, Result};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;
use ureq::http::Uri;

/// How long reaching the page may take, and how long its answer may.
const WAIT: Duration = Duration::from_secs(5);

/// The most of an answer read for its status and headers.
const HEAD: usize = 16 * 1024;

/// How far a network joined reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// The page answered as it does.
    Online,
    /// The network answered in the page's stead: it wants a login in a
    /// browser first, at the page it sends on to where it names one.
    Login(Option<String>),
    /// Nothing answered, or not as either would: why.
    Offline(String),
}

impl std::fmt::Display for Reach {
    /// How far a network reaches, said of the network.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reach::Online => f.write_str("reaches the internet"),
            Reach::Login(Some(page)) => write!(f, "wants a login in a browser first, at {page}"),
            Reach::Login(None) => f.write_str("wants a login in a browser first"),
            Reach::Offline(why) => write!(f, "does not reach the internet: {why}"),
        }
    }
}

/// Ask `page`, a plain HTTP address, looking its host up in `servers`.
pub fn probe(page: &str, servers: &[Ipv4Addr]) -> Reach {
    match answer(page, servers) {
        Ok((code, location)) => judge(page, code, location),
        Err(e) => Reach::Offline(format!("{e:#}")),
    }
}

/// How far a network reaches, by what `page` answered: 204 is the page
/// itself, another answer a browser would show or follow is the network's
/// login, and any other is neither.
fn judge(page: &str, code: u16, location: Option<String>) -> Reach {
    match code {
        204 => Reach::Online,
        200..=399 => Reach::Login(location),
        _ => Reach::Offline(format!("{page} answered {code}")),
    }
}

/// What `page` answers: its status, and where it sends on to.
fn answer(page: &str, servers: &[Ipv4Addr]) -> Result<(u16, Option<String>)> {
    let uri: Uri = page
        .parse()
        .with_context(|| format!("{page} is not an address"))?;
    let (host, authority) = match (uri.host(), uri.authority()) {
        (Some(host), Some(authority)) => (host, authority.as_str()),
        _ => bail!("{page} names no host"),
    };
    let port = uri.port_u16().unwrap_or(80);
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let mut tried = Vec::new();
    for address in dns::lookup(host, servers)? {
        let at = SocketAddr::new(IpAddr::V4(address), port);
        match TcpStream::connect_timeout(&at, WAIT) {
            Ok(stream) => {
                return ask(stream, authority, path).with_context(|| format!("ask {page} at {at}"))
            }
            Err(e) => tried.push(format!("{at}: {e}")),
        }
    }
    Err(anyhow!("could not reach {host}: {}", tried.join("; ")))
}

/// Ask over `stream` for `path` of `authority`, and read the head of the
/// answer. Some networks' gateways answer only a request whose header
/// names are spelled as browsers spell them, Host with a capital, and the
/// HTTP client the rest of the recovery uses writes every name in small
/// letters, so the request is written here as a browser writes it.
fn ask(mut stream: TcpStream, authority: &str, path: &str) -> Result<(u16, Option<String>)> {
    stream
        .set_read_timeout(Some(WAIT))
        .context("time the connection")?;
    stream
        .set_write_timeout(Some(WAIT))
        .context("time the connection")?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .context("send the request")?;
    let mut head = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                bail!("no answer in {} s", WAIT.as_secs())
            }
            Err(e) => return Err(e).context("read the answer"),
        };
        ensure!(
            n > 0,
            "the connection closed before the answer's head ended"
        );
        head.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        if response
            .parse(&head)
            .context("read the head of the answer")?
            .is_complete()
        {
            let code = response.code.context("the answer has no status")?;
            let location = response
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("location"))
                .map(|h| String::from_utf8_lossy(h.value).into_owned());
            return Ok((code, location));
        }
        ensure!(
            head.len() < HEAD,
            "the head of the answer runs past {HEAD} bytes"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// A server on the loopback answering one request with `answer`, and
    /// only a request that spells its Host header as browsers do, as some
    /// gateways answer.
    fn gateway(answer: &'static str) -> String {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 512];
            while !request.ends_with(b"\r\n\r\n") {
                let n = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..n]);
            }
            if String::from_utf8_lossy(&request).contains("\r\nHost: ") {
                stream.write_all(answer.as_bytes()).unwrap();
            }
            // Held open, as such a gateway holds it.
            thread::sleep(Duration::from_secs(1));
        });
        format!("http://127.0.0.1:{port}/generate_204")
    }

    #[test]
    fn the_page_itself_answers_204() {
        let page = gateway("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(probe(&page, &[]), Reach::Online);
    }

    #[test]
    fn a_network_that_wants_a_login_sends_on_to_its_page() {
        let page = gateway("HTTP/1.1 302 Moved Temporarily\r\nCache-Control: no-cache\r\nLocation: http://192.168.64.254:2060/redirect/?pip=192.168.72.76\r\n\r\n");
        let login = probe(&page, &[]);
        assert_eq!(
            login,
            Reach::Login(Some(
                "http://192.168.64.254:2060/redirect/?pip=192.168.72.76".into()
            )),
            "the head is read as it ends, the rest not waited for"
        );
    }

    #[test]
    fn a_page_shown_in_the_pages_stead_is_a_login_and_an_error_is_neither() {
        assert_eq!(judge("p", 200, None), Reach::Login(None));
        assert_eq!(
            judge("p", 307, Some("http://login".into())),
            Reach::Login(Some("http://login".into()))
        );
        assert_eq!(
            judge("http://a/generate_204", 503, None),
            Reach::Offline("http://a/generate_204 answered 503".into())
        );
    }

    #[test]
    fn nothing_listening_reaches_nothing() {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let Reach::Offline(why) = probe(&format!("http://127.0.0.1:{port}/generate_204"), &[])
        else {
            panic!("a closed port reaches nothing")
        };
        assert!(why.contains("could not reach 127.0.0.1"), "{why}");
        assert!(
            matches!(
                probe("http://connect.rom.miui.com/generate_204", &[]),
                Reach::Offline(_)
            ),
            "a name without a DNS server to ask"
        );
    }
}
