//! Backend login metadata has one aggregate JSON bound; administrative custom
//! metadata retains its own policy. Counting never buffers a second map.
use std::{
    collections::BTreeMap,
    io::{self, Write},
};

// Equal to the ordinary HTTP request body ceiling. Encoded escaped bytes count.
pub(crate) const MAX_BYTES: usize = 256 * 1024;

pub(crate) fn within_limit(metadata: &BTreeMap<String, String>) -> bool {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > MAX_BYTES.saturating_sub(self.0) {
                return Err(io::Error::other("login metadata exceeds capacity"));
            }
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Count(0), metadata).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_encoded_boundary_includes_json_escaping_without_a_copy() {
        let fixed = br#"{"k":""}"#.len();
        let mut map = BTreeMap::from([("k".into(), "x".repeat(MAX_BYTES - fixed))]);
        assert!(within_limit(&map));
        map.insert("k".into(), "x".repeat(MAX_BYTES - fixed + 1));
        assert!(!within_limit(&map));
        map.insert("k".into(), "\n".repeat(MAX_BYTES / 2));
        assert!(!within_limit(&map));
    }
}
