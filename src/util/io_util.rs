use std::io;
use std::sync::Arc;
use std::time::Duration;
use futures_util::SinkExt;
use tfserver::codec::codec_trait::TfCodec;
use tfserver::futures_util::future::BoxFuture;
use tfserver::structures::transport::AsyncReadWrite;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;
use tokio_util::bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, Framed};

pub struct EndPointSideChannel {
    pub from_endpoint_snd: Sender<Bytes>,
    pub to_endpoint_rcv: Receiver<Bytes>,
}

pub struct SenderSideChannel {
    pub to_endpoint_snd: Sender<Bytes>,
    pub from_endpoint_rcv: Receiver<Bytes>,
}

pub fn handler_channel() -> (EndPointSideChannel, SenderSideChannel) {
    let first = mpsc::channel(128);
    let second = mpsc::channel(128);
    (
        EndPointSideChannel {
            from_endpoint_snd: first.0,
            to_endpoint_rcv: second.1,
        },
        SenderSideChannel {
            to_endpoint_snd: second.0,
            from_endpoint_rcv: first.1,
        },
    )
}

pub type PacketAnalyzeFuture<'a> = BoxFuture<'a, ()>;


pub type PacketAnalyzeFn<A> =
    for<'a> fn(Option<Arc<A>>, &'a [u8]) -> PacketAnalyzeFuture<'a>;

pub async fn hardwire_proxy_to_endpoint<A>(
    mut proxy_channel: SenderSideChannel,
    mut endpoint_channel: SenderSideChannel,
    mut stop_sig: broadcast::Receiver<()>,
    mut on_client_packet: Option<PacketAnalyzeFn<A>>,
    mut on_server_packet: Option<PacketAnalyzeFn<A>>,
    app_data_client: Option<Arc<A>>,
    app_data_server: Option<Arc<A>>,
) {
    loop {
        tokio::select! {
            proxy_data = proxy_channel.from_endpoint_rcv.recv() => {
                    match proxy_data {
                        Some(data) => {
                            if let Some(cli_packet) = on_client_packet.as_mut(){
                                cli_packet(app_data_client.clone(), data.as_ref()).await;
                            }
                            if endpoint_channel.to_endpoint_snd.send(data).await.is_err() {
                                return;
                            }
                        }
                        None => return,
                    }
            }
            network_data = endpoint_channel.from_endpoint_rcv.recv()  => {
                match network_data {
                        Some(data) => {
                            if let Some(cli_packet) = on_server_packet.as_mut(){
                                cli_packet(app_data_server.clone(), data.as_ref()).await;
                            }
                            if proxy_channel.to_endpoint_snd.send(data).await.is_err() {
                                return;
                            }
                        }
                        None => return,
                    }
            }
             _ = stop_sig.recv() => return,
        }
    }
}


pub async fn send_message<T, C: TfCodec>(
    stream: &mut Framed<T, C>,
    message: Bytes,
) -> Result<(), io::Error> where
    T: AsyncWrite + Unpin {
    stream.send(message).await
}

pub async fn receive_message<T, C: TfCodec>(
    stream: &mut Framed<T, C>,
) -> Result<Option<BytesMut>, bool> where
    T: AsyncRead + Unpin {
    use futures_util::StreamExt;
    match stream.next().await {
        Some(data) => match data {
            Ok(data) => {
                Ok(Some(data))
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof => {
                    eprintln!("Client  disconnected");
                    Err(true)
                }
                std::io::ErrorKind::InvalidData => {
                    eprintln!("Frame exceeded maximum size {}", e);
                    Err(false)
                }
                _ => {
                    eprintln!("IO error reading frame: {}", e);
                    Err(false)
                }
            },
        },
        None => Err(true),
    }
}