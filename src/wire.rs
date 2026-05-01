use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::error::{Error, Result};
use crate::proto::MAX_FRAME_LEN;

pub type FramedStream<S> = Framed<S, LengthDelimitedCodec>;

pub fn frame<S>(stream: S) -> FramedStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    LengthDelimitedCodec::builder()
        .length_field_length(4)
        .max_frame_length(MAX_FRAME_LEN)
        .new_framed(stream)
}

pub async fn send_bytes<S>(framed: &mut FramedStream<S>, payload: Vec<u8>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    framed.send(Bytes::from(payload)).await?;
    Ok(())
}

pub async fn recv_bytes<S>(framed: &mut FramedStream<S>) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match framed.next().await {
        Some(Ok(b)) => Ok(b.to_vec()),
        Some(Err(e)) => Err(e.into()),
        None => Err(Error::Closed),
    }
}

pub async fn send_postcard<S, T>(framed: &mut FramedStream<S>, value: &T) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = postcard::to_stdvec(value)?;
    send_bytes(framed, bytes).await
}

pub async fn recv_postcard<S, T>(framed: &mut FramedStream<S>) -> Result<T>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: DeserializeOwned,
{
    let bytes = recv_bytes(framed).await?;
    Ok(postcard::from_bytes(&bytes)?)
}
