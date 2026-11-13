//! Minimal Dash P2P connection for probing a single peer. The SPV client's peers are
//! driven by background tasks, which doesn't fit a probe that blocks on each reply.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use dashcore::Network;
use dashcore::consensus::encode;
use dashcore::network::message::{NetworkMessage, RawNetworkMessage, RawNetworkMessageCodec};
use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_util::codec::FramedRead;

pub struct Message(NetworkMessage);

impl Message {
    pub fn inner(&self) -> &NetworkMessage {
        &self.0
    }
}

pub struct Peer {
    reader: FramedRead<OwnedReadHalf, RawNetworkMessageCodec>,
    writer: OwnedWriteHalf,
    magic: u32,
}

impl Peer {
    /// No handshake: the caller drives it.
    pub async fn connect(addr: SocketAddr, timeout_secs: u64, network: Network) -> Result<Self> {
        let stream =
            tokio::time::timeout(Duration::from_secs(timeout_secs), TcpStream::connect(addr))
                .await
                .map_err(|_| anyhow!("connect to {addr} timed out after {timeout_secs}s"))?
                .with_context(|| format!("connect to {addr}"))?;

        let (read_half, writer) = stream.into_split();

        Ok(Self {
            reader: FramedRead::new(read_half, RawNetworkMessageCodec),
            writer,
            magic: network.magic(),
        })
    }

    pub async fn send_message(&mut self, message: NetworkMessage) -> Result<()> {
        let raw = RawNetworkMessage {
            magic: self.magic,
            payload: message,
        };

        self.writer.write_all(&encode::serialize(&raw)).await.context("send message")?;

        Ok(())
    }

    /// Next message from the peer, or `None` once it closes the connection.
    pub async fn receive_message(&mut self) -> Result<Option<Message>> {
        match self.reader.next().await {
            Some(Ok(raw)) => Ok(Some(Message(raw.payload))),
            Some(Err(e)) => Err(e).context("decode message"),
            None => Ok(None),
        }
    }
}
