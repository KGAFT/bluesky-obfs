use crate::util::io_util::{handler_channel, receive_message, send_message, EndPointSideChannel, SenderSideChannel};
use crate::codec::tls_codec::TlsCodec;
use std::net::SocketAddr;
use tfserver::futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_util::bytes::Bytes;
use tokio_util::codec::Framed;

pub struct ProxyInterface {
    connection_task: Option<tokio::task::JoinHandle<()>>,
    stop_sig: broadcast::Sender<()>,
}

impl ProxyInterface {
    pub async fn new(port: u16) -> (Self, SenderSideChannel) {
        let listener =
            TcpListener::bind("127.0.0.1:".to_string() + &port.to_string()).await;
        let channel = handler_channel();
        let stop_sig = broadcast::channel(1);
        let connection_task = tokio::task::spawn(async move {
            handle_connect(listener.unwrap(), channel.0, stop_sig.1).await;
        });
        (
            Self {
                connection_task: Some(connection_task),
                stop_sig: stop_sig.0,
            },
            channel.1,
        )
    }

    pub async fn join_proxy(&mut self) {
        if let Some(handle) = self.connection_task.take() {
            handle.await.unwrap();
        }
    }

    pub async fn stop_proxy(&mut self) {
        self.stop_sig.send(()).unwrap();
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

async fn handle_connect(
    listener: TcpListener,
    channel: EndPointSideChannel,
    mut stop_sig: broadcast::Receiver<()>,
) {
    let tx = channel.from_endpoint_snd;
    let mut rx = channel.to_endpoint_rcv;
    let client = await_client(listener, &mut stop_sig).await;
    if client.is_none() {
        return;
    }
    let mut client = client.unwrap();
    client.0.set_nodelay(true);
    let dest = proxy_setup(&mut client.0).await;
    if dest.is_none() {
        return;
    }
    let addr = client.1;
    let mut cli_stream = Framed::new(client.0, TlsCodec::new());

    loop {
        tokio::select! {
        _ = stop_sig.recv() => return,

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
                             eprintln!("Client disconnected");
                            return;
                        }
                    }
                }}

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

async fn proxy_setup(client: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(4096);
    loop {
        let mut tmp = [0u8; 1024];
        let n = client.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|x| x == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return None;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    request.parse(&buf).ok()?;
    let method = request.method?;
    let path = request.path?;
    println!("{method} {path}");
    if method.eq_ignore_ascii_case("CONNECT") {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .ok()?;

        // CRITICAL FIX: Flush the socket so wreq receives the response immediately
        client.flush().await.ok()?;

        return Some(path.to_string());
    }
    None
}

async fn await_client(
    listener: TcpListener,
    stop_sig: &mut broadcast::Receiver<()>,
) -> Option<(TcpStream, SocketAddr)> {
    tokio::select! {
      _ = stop_sig.recv() => None,

      result = async {
          loop {
              match listener.accept().await {
                  Ok(client) => break client,
                  Err(e) => {
                      eprintln!("accept failed: {e}");
                  }
              }
          }
      } => Some(result),
  }
}