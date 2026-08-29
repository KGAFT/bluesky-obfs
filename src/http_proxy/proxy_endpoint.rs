use crate::codec::tls_codec::TlsCodec;
use crate::util::io_util::{
    EndPointSideChannel, SenderSideChannel, handler_channel, receive_message, send_message,
};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tfserver::futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::time::timeout;
use tokio_util::codec::Framed;

pub struct ProxyEndpoint {
    connection_task: Option<tokio::task::JoinHandle<()>>,
    stop_sig: broadcast::Sender<()>,
}

impl ProxyEndpoint {
    pub async fn new(destination: String) -> io::Result<(Self, SenderSideChannel)> {
        eprintln!("[FakeCodec DEBUG] starting connect to destination: {}", destination);
        let connection = match timeout(Duration::from_secs(10), TcpStream::connect(destination.clone())).await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("[FakeCodec DEBUG] Connection to {} timed out after 10 seconds", destination);
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Connection timed out"));
            }
        };
        if let Err(e) = connection {
            eprintln!("[FakeCodec DEBUG] Failed to connect to destination {}: {}", destination, e);
            return Err(e);
        }
        eprintln!("[FakeCodec DEBUG] connected to destination: {}", destination);
        let connection = connection?;
        let channel = handler_channel();
        let stop_sig = broadcast::channel(1);
        let connection_task = tokio::task::spawn(async move {
            endpoint_main(connection, channel.0, stop_sig.1).await;
        });
        Ok((
            Self {
                connection_task: Some(connection_task),
                stop_sig: stop_sig.0,
            },
            channel.1,
        ))
    }

    pub async fn new_d(destination: SocketAddr) -> io::Result<(Self, SenderSideChannel)> {
        let connection = TcpStream::connect(destination).await?;
        let channel = handler_channel();
        let stop_sig = broadcast::channel(1);
        let connection_task = tokio::task::spawn(async move {
            endpoint_main(connection, channel.0, stop_sig.1).await;
        });
        Ok((
            Self {
                connection_task: Some(connection_task),
                stop_sig: stop_sig.0,
            },
            channel.1,
        ))
    }

    pub async fn join_endpoint(&mut self) {
        if let Some(handle) = self.connection_task.take() {
            handle.await.unwrap();
        }
    }

    pub async fn stop_endpoint(&mut self) {
        self.stop_sig.send(()).unwrap();
    }

    pub async fn abort_endpoint(&mut self) {
        self.stop_endpoint().await;
        if let Some(handle) = self.connection_task.take() {
            handle.abort()
        }
    }
}

impl Drop for ProxyEndpoint {
    fn drop(&mut self) {
        let _ = self.stop_sig.send(());
    }
}

pub async fn endpoint_main(
    mut connect: TcpStream,
    channel: EndPointSideChannel,
    mut stop_sig: broadcast::Receiver<()>,
) {
    let tx = channel.from_endpoint_snd;
    let mut rx = channel.to_endpoint_rcv;
    let mut buf = [0u8; 16 * 1024];
    let mut connect = Framed::new(connect, TlsCodec::new());
    loop {
        tokio::select! {
                 _ = stop_sig.recv() => return,
                read = receive_message(&mut connect)=> {
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
                }

            }
                data = rx.recv() => {
                    match data {
                        Some(data) => {
                            if send_message(&mut connect, data).await.is_err() {
                                return;
                            }
                        }
                        None => return,
                    }
                }


        }
    }
}
