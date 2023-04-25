use std::{pin::Pin, task::{Context, Poll}};

use tokio::io::{AsyncRead, ReadBuf};
use bytes::{Bytes, BytesMut, BufMut};
use futures::{Stream, stream, StreamExt};
use pin_project_lite::pin_project;

pin_project! {
    /// Stream of bytes.
    pub struct ByteStream {
        size_hint: Option<usize>,
        #[pin]
        inner: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static>>,
    }
}

#[allow(dead_code)]
impl ByteStream {
    /// Create a new `ByteStream` by wrapping a `futures` stream.
    pub fn new<S>(stream: S) -> ByteStream
    where
        S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
    {
        ByteStream {
            size_hint: None,
            inner: Box::pin(stream),
        }
    }

    pub(crate) fn size_hint(&self) -> Option<usize> {
        self.size_hint
    }

    pub fn into_async_read(self) -> impl AsyncRead + Send + 'static {
        ImplAsyncRead::new(self.inner)
    }
}

impl From<Vec<u8>> for ByteStream {
    fn from(buf: Vec<u8>) -> ByteStream {
        ByteStream {
            size_hint: Some(buf.len()),
            inner: Box::pin(stream::once(async move { Ok(Bytes::from(buf)) })),
        }
    }
}

impl std::fmt::Debug for ByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "<ByteStream size_hint={:?}>", self.size_hint)
    }
}

impl Stream for ByteStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.inner.poll_next(cx)
    }
}

pin_project! {
    struct ImplAsyncRead {
        buffer: BytesMut,
        #[pin]
        stream: futures::stream::Fuse<Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>>,
    }
}

impl ImplAsyncRead {
    fn new(stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>) -> Self {
        ImplAsyncRead {
            buffer: BytesMut::new(),
            stream: stream.fuse(),
        }
    }
}

impl AsyncRead for ImplAsyncRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        if this.buffer.is_empty() {
            match futures::ready!(this.stream.poll_next(cx)) {
                None => return Poll::Ready(Ok(())),
                Some(Err(e)) => return Poll::Ready(Err(e)),
                Some(Ok(bytes)) => {
                    this.buffer.put(bytes);
                }
            }
        }
        let available = std::cmp::min(buf.remaining(), this.buffer.len());
        let bytes = this.buffer.split_to(available);
        buf.put_slice(&bytes);
        Poll::Ready(Ok(()))
    }
}