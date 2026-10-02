//! Secret-bearing JSON buffers must wipe old allocations when they grow, not
//! merely their last allocation. Limits are chosen by the owning protocol.
use serde::Serialize;
use zeroize::Zeroizing;

pub(crate) enum Error {
    TooLarge,
    Serialization,
}

pub(crate) fn to_vec(value: &impl Serialize, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    struct Writer {
        bytes: Zeroizing<Vec<u8>>,
        limit: usize,
        overflowed: bool,
    }
    impl std::io::Write for Writer {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            let Some(next_len) = self
                .bytes
                .len()
                .checked_add(input.len())
                .filter(|size| *size <= self.limit)
            else {
                self.overflowed = true;
                return Err(std::io::Error::other("secret JSON exceeds protocol limit"));
            };
            if next_len > self.bytes.capacity() {
                let capacity = next_len
                    .max(self.bytes.capacity().saturating_mul(2))
                    .min(self.limit);
                let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
                grown.extend_from_slice(&self.bytes);
                self.bytes = grown;
            }
            self.bytes.extend_from_slice(input);
            Ok(input.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        bytes: Zeroizing::new(Vec::new()),
        limit,
        overflowed: false,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.overflowed {
            Error::TooLarge
        } else {
            Error::Serialization
        }
    })?;
    Ok(writer.bytes)
}
