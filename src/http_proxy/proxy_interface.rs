use crate::util::io_util::{handler_channel, receive_message, send_message, EndPointSideChannel, SenderSideChannel};
use crate::codec::tls_codec::TlsCodec;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex};
use tokio_util::bytes::Bytes;
use tokio_util::codec::Framed;

/// Upper bound on a request body accepted during local proxy setup. The setup
/// exchange is a single CONNECT or small GET; anything larger is a bug or an
/// attempt to exhaust memory.
const MAX_SETUP_BODY_LEN: usize = 1024 * 1024;

pub struct ProxyInterface {
    connection_task: Option<tokio::task::JoinHandle<()>>,
    stop_sig: broadcast::Sender<()>,
    connection_dest: Arc<Mutex<Option<String>>>,
}

impl ProxyInterface {
    /// Bind the local setup proxy.
    ///
    /// The bind is awaited here rather than inside the spawned task: a failure
    /// (a second instance, or the port squatted) used to panic a detached task
    /// and surface much later as an unexplained handshake failure. Now it is an
    /// ordinary error at the call site.
    pub async fn new(port: u16) -> std::io::Result<(Self, SenderSideChannel)> {
        let listener =
            TcpListener::bind("127.0.0.1:".to_string() + &port.to_string()).await?;
        let channel = handler_channel();
        let stop_sig = broadcast::channel(1);
        let connection_dest = Arc::new(Mutex::new(None));
        let connection_dest_task = connection_dest.clone();
        let connection_task = tokio::task::spawn(async move {
            handle_connect(listener, channel.0, stop_sig.1, connection_dest_task).await;
        });
        Ok((
            Self {
                connection_task: Some(connection_task),
                stop_sig: stop_sig.0,
                connection_dest,
            },
            channel.1,
        ))
    }

    pub async fn join_proxy(&mut self) {
        if let Some(handle) = self.connection_task.take() {
            // The task may already be gone (aborted, or panicked); joining is
            // best effort and must not take the caller down with it.
            let _ = handle.await;
        }
    }

    pub async fn connection_dest(&mut self) -> Option<String> {
        self.connection_dest.lock().await.clone()
    }

    pub async fn stop_proxy(&mut self) {
        // Errors only when there are no receivers left, i.e. the task already
        // exited — which is exactly the state this call is trying to reach.
        let _ = self.stop_sig.send(());
    }

    pub async fn abort_proxy(&mut self) {
        self.stop_proxy().await;
        if let Some(handle) = self.connection_task.take() {
            handle.abort()
        }
    }
}

impl Drop for ProxyInterface {
    fn drop(&mut self) {
        let _ = self.stop_sig.send(());
    }
}

/// Result of parsing the initial client request during proxy setup.
struct SetupResult {
    /// "host:port" of the requested destination — handed off via
    /// `connection_dest` for whatever owns dialing the real target.
    dest: String,
    /// For plain HTTP (non-CONNECT) requests, the full request (headers + any
    /// body already read off the client socket) that must go out as the
    /// first packet on the data channel, since it was consumed from the
    /// socket in order to parse it and find `dest`.
    initial_request: Option<Vec<u8>>,
}

async fn handle_connect(
    listener: TcpListener,
    channel: EndPointSideChannel,
    mut stop_sig: broadcast::Receiver<()>,
    connection_dest: Arc<Mutex<Option<String>>>,
) {
    let tx = channel.from_endpoint_snd;
    let mut rx = channel.to_endpoint_rcv;
    let client = await_client(&listener, &mut stop_sig).await;
    if client.is_none() {
        return;
    }
    let mut client = client.unwrap();
    client.0.set_nodelay(true).ok();
    let setup = proxy_setup(&mut client.0).await;
    let setup = match setup {
        Some(s) => s,
        None => return,
    };
    connection_dest.lock().await.replace(setup.dest);
    let _addr = client.1;
    let mut cli_stream = Framed::new(client.0, TlsCodec::new());

    // Plain-HTTP case: the request was already consumed off the client
    // socket while parsing it for `dest`, so it must go out over the data
    // channel as the first packet before we start relaying further reads.
    // (CONNECT has nothing to replay — the 200 response already went
    // straight back to the client and the tunnel starts empty.)
    if let Some(initial) = setup.initial_request {
        if tx.send(Bytes::from(initial)).await.is_err() {
            return;
        }
    }

    loop {
        tokio::select! {
        _ = stop_sig.recv() => return,

        // Bytes coming from the local client -> forward to the data channel.
        read = receive_message(&mut cli_stream)=> {
                match read {
                    Ok(res) => {
                        match res {
                            Some(data) => {
                                if tx.send(data.freeze()).await.is_err(){
                                    return
                                }
                            }
                            None => {}
                        }
                    }
                    Err(disconnect) => {
                        if disconnect{
                             dbg_log!("Client disconnected");
                            return;
                        }
                    }
                }}

        // Bytes coming back from the data channel (the target's response) ->
        // write to the local client.
        data = rx.recv() => {
            match data {
                Some(data) => {
                    if send_message(&mut cli_stream, data).await.is_err() {
                        return;
                    }
                }
                None => return,
            }
        }
    }
    }
}

async fn proxy_setup(client: &mut TcpStream) -> Option<SetupResult> {
    let mut buf = Vec::with_capacity(4096);
    let header_len;
    loop {
        let mut tmp = [0u8; 1024];
        let n = client.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_len = pos;
            break;
        }
        if buf.len() > 16 * 1024 {
            return None;
        }
    }

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    request.parse(&buf).ok()?;
    let method = request.method?.to_string();
    let path = request.path?.to_string();

    println!("{method} {path}");

    if method.eq_ignore_ascii_case("CONNECT") {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .ok()?;

        client.flush().await.ok()?;

        return Some(SetupResult {
            dest: path,
            initial_request: None,
        });
    }


    let dest = extract_http_dest(&path, &request)?;

    let content_length = request
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let is_chunked = request
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Transfer-Encoding"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    // `content_length` is attacker-controlled: it is whatever the local client
    // wrote in the header. Allocating it directly is a free OOM for any process
    // that can reach this port. The 16 KiB guard above only covers the header
    // scan, so bound the body explicitly here and in the chunked path.
    if content_length > MAX_SETUP_BODY_LEN {
        return None;
    }

    if is_chunked {
        read_chunked_body(client, &mut buf, header_len).await?;
    } else if content_length > 0 {
        let already_have = buf.len() - header_len;
        if already_have < content_length {
            let remaining = content_length - already_have;
            let mut body = vec![0u8; remaining];
            client.read_exact(&mut body).await.ok()?;
            buf.extend_from_slice(&body);
        }
    }

    Some(SetupResult {
        dest,
        initial_request: Some(buf),
    })
}


async fn read_chunked_body(client: &mut TcpStream, buf: &mut Vec<u8>, body_start: usize) -> Option<()> {
    let mut pos = body_start;

    loop {
        // `buf` grows with every chunk and nothing else bounds it, so a peer
        // that keeps sending chunks can grow it without limit.
        if buf.len() > MAX_SETUP_BODY_LEN {
            return None;
        }
        let size_line_end = loop {
            if let Some(rel) = buf[pos..].windows(2).position(|w| w == b"\r\n") {
                break pos + rel + 2;
            }
            if !read_more(client, buf).await? {
                return None;
            }
        };

        let size_line = std::str::from_utf8(&buf[pos..size_line_end - 2]).ok()?;
        let size_str = size_line.split(';').next().unwrap_or(size_line).trim();
        let chunk_size = usize::from_str_radix(size_str, 16).ok()?;

        if chunk_size == 0 {
            pos = size_line_end;
            loop {
                if let Some(rel) = buf[pos..].windows(4).position(|w| w == b"\r\n\r\n") {
                    pos += rel + 4;
                    break;
                }
                if !read_more(client, buf).await? {
                    return None;
                }
            }
            buf.truncate(pos);
            return Some(());
        }

        let chunk_end = size_line_end + chunk_size + 2;
        while buf.len() < chunk_end {
            if !read_more(client, buf).await? {
                return None;
            }
        }

        pos = chunk_end;
    }
}


async fn read_more(client: &mut TcpStream, buf: &mut Vec<u8>) -> Option<bool> {
    let mut tmp = [0u8; 4096];
    let n = client.read(&mut tmp).await.ok()?;
    if n == 0 {
        return Some(false);
    }
    buf.extend_from_slice(&tmp[..n]);
    Some(true)
}


fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

fn extract_http_dest(path: &str, request: &httparse::Request) -> Option<String> {
    if let Some(rest) = path
        .strip_prefix("http://")
        .or_else(|| path.strip_prefix("https://"))
    {
        let host_port = rest.split('/').next().unwrap_or(rest);
        return Some(match host_port.split_once(':') {
            Some((h, p)) => format!("{h}:{p}"),
            None => format!("{host_port}:80"),
        });
    }

    request
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Host"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(|host| {
            if host.contains(':') {
                host.to_string()
            } else {
                format!("{host}:80")
            }
        })
}

async fn await_client(
    listener: &TcpListener,
    stop_sig: &mut broadcast::Receiver<()>,
) -> Option<(TcpStream, SocketAddr)> {
    tokio::select! {
        _ = stop_sig.recv() => None,
        result = listener.accept() => result.ok(),
    }
}