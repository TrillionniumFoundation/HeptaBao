// Keep the alphabetical key order of the original serde_json::Value map.
// Borrow potentially large input while retaining exactly its original JSON bytes.
#[derive(Serialize)]
struct RequestBinding<'a> {
	args: &'a [String],
	cpu_quota_percent: Option<u16>,
	cwd: Option<&'a str>,
	env: &'a BTreeMap<String, String>,
	executable: &'a str,
	host: &'a str,
	memory_max_bytes: Option<u64>,
	nice: Option<u8>,
	stdin: Option<&'a str>,
	timeout_seconds: Option<u64>,
}
fn request_binding(params: &ProcessStartParams) -> RequestBinding<'_> {
	RequestBinding {
		args: &params.args,
		cpu_quota_percent: params.cpu_quota_percent,
		cwd: params.cwd.as_deref(),
		env: &params.env,
		executable: &params.executable,
		host: &params.host,
		memory_max_bytes: params.memory_max_bytes,
		nice: params.nice,
		stdin: params.stdin.as_deref(),
		timeout_seconds: params.timeout_seconds,
	}
}
struct RequestHashWriter(Sha256);
impl Write for RequestHashWriter {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		self.0.update(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}
pub(crate) fn request_digest(params: &ProcessStartParams) -> Result<String> {
	let mut writer = RequestHashWriter(Sha256::new());
	serde_json::to_writer(&mut writer, &request_binding(params))?;
	let digest = writer.0.finalize();
	let mut hex = String::with_capacity(64);
	const HEX: &[u8; 16] = b"0123456789abcdef";
	for byte in digest {
		hex.push(HEX[(byte >> 4) as usize] as char);
		hex.push(HEX[(byte & 15) as usize] as char);
	}
	Ok(hex)
}

// Retain the old prefix only for readable legacy metadata. New idempotent
// requests compare all 256 bits, and legacy bindings never silently relaunch.
fn fingerprint(digest: &str) -> u64 {
	digest
		.get(..16)
		.and_then(|prefix| u64::from_str_radix(prefix, 16).ok())
		.unwrap_or(0)
}
