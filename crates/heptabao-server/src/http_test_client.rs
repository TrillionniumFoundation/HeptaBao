//! Test client reads share one deadline without resetting peer socket options.
//!
//! Darwin can reject SO_RCVTIMEO after the peer closes with unread upload data,
//! even while its complete response remains buffered. The server under test
//! still uses its real DeadlineStream. This client only observes already sent
//! bytes through the existing Tokio readiness driver.
use super::*;
use tokio::io::AsyncReadExt;

pub(super) struct DeadlineClientReader {
    stream: tokio::net::TcpStream,
    runtime: tokio::runtime::Runtime,
    deadline: Instant,
}

impl DeadlineClientReader {
    pub(super) fn new(stream: TcpStream, deadline: Instant) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let stream = {
            let _entered = runtime.enter();
            tokio::net::TcpStream::from_std(stream)?
        };
        Ok(Self {
            stream,
            runtime,
            deadline,
        })
    }

    pub(super) fn read_exact(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        let expired = || io::Error::new(io::ErrorKind::TimedOut, "original TLS fixture deadline");
        if Instant::now() >= self.deadline {
            return Err(expired());
        }
        let stream = &mut self.stream;
        let deadline = self.deadline;
        self.runtime.block_on(async {
            tokio::time::timeout_at(deadline.into(), stream.read_exact(buffer))
                .await
                .map_err(|_| expired())?
        })?;
        if Instant::now() >= deadline {
            return Err(expired());
        }
        Ok(())
    }
}
