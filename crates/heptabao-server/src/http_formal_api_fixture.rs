//! Owned loopback TLS for the formal three-voter Service component fixture.
//! The real listener address is configured before HA startup. This helper runs
//! the production parser/dispatch/writer; it is not a production serve or a
//! physical-host qualification.
use super::*;
use std::net::Shutdown;
use std::thread::JoinHandle;

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

pub(crate) struct FormalApiListener {
    listener: TcpListener,
    server_tls: Arc<ServerConfig>,
    client_tls: Arc<rustls::ClientConfig>,
    expected_leaf: Vec<u8>,
}

struct RequestWorker {
    thread: Option<JoinHandle<io::Result<()>>>,
    client: TcpStream,
    server: TcpStream,
}

impl RequestWorker {
    fn join(mut self) -> FixtureResult<()> {
        let thread = self
            .thread
            .take()
            .ok_or("formal TLS worker already joined")?;
        thread.join().map_err(|_| "formal TLS worker panicked")??;
        Ok(())
    }
}
impl Drop for RequestWorker {
    fn drop(&mut self) {
        let _ = self.client.shutdown(Shutdown::Both);
        let _ = self.server.shutdown(Shutdown::Both);
        if let Some(thread) = self.thread.take() {
            // The worker owns the original request deadline. It must actually
            // finish before the fixture releases its Service/Raft owners.
            let _ = thread.join();
        }
    }
}

impl FormalApiListener {
    pub(crate) fn bind(
        directory: &std::path::Path,
        node_id: u64,
        address: Option<SocketAddr>,
    ) -> FixtureResult<Self> {
        let listener = TcpListener::bind(address.unwrap_or("127.0.0.1:0".parse()?))?;
        listener.set_nonblocking(true)?;
        let cert_path = directory.join(format!("voter-{node_id}.crt"));
        let key_path = directory.join(format!("voter-{node_id}.key"));
        let cert_bytes = bounded_file(&cert_path, false)?;
        let key_bytes = bounded_file(&key_path, true)?;
        let certificates = rustls_pemfile::certs(&mut BufReader::new(cert_bytes.as_slice()))
            .collect::<Result<Vec<_>, _>>()?;
        let expected_leaf = certificates
            .first()
            .ok_or("formal API leaf absent")?
            .as_ref()
            .to_vec();
        let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))?
            .ok_or("formal API private key absent")?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_tls = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certificates, key)?;
        configure_api_alpn(&mut server_tls);
        let ca_bytes = bounded_file(&directory.join("ca.crt"), false)?;
        let mut roots = RootCertStore::empty();
        for certificate in rustls_pemfile::certs(&mut BufReader::new(ca_bytes.as_slice())) {
            roots.add(certificate?)?;
        }
        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            listener,
            server_tls: Arc::new(server_tls),
            client_tls: Arc::new(client_tls),
            expected_leaf,
        })
    }

    pub(crate) fn address(&self) -> FixtureResult<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub(crate) fn origin(&self) -> FixtureResult<String> {
        Ok(format!("https://{}", self.address()?))
    }

    pub(crate) fn leaf_sha256(&self) -> [u8; 32] {
        crypto::digest(&self.expected_leaf)
    }

    pub(crate) fn exchange(
        &self,
        service: &Arc<Mutex<Service>>,
        request: &[u8],
        deadline: Instant,
        missing_forward: bool,
    ) -> FixtureResult<Zeroizing<Vec<u8>>> {
        let remaining = || {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .ok_or("formal TLS original deadline")
        };
        let client_socket = TcpStream::connect_timeout(&self.address()?, remaining()?)?;
        let client_address = client_socket.local_addr()?;
        let (server_socket, peer) = loop {
            match self.listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    remaining()?;
                    std::thread::yield_now();
                }
                Err(error) => return Err(error.into()),
            }
        };
        if peer != client_address || !peer.ip().is_loopback() {
            return Err("formal TLS listener accepted a different client".into());
        }
        // Darwin accept inherits O_NONBLOCK from the listener. The real TLS
        // stream uses its existing absolute socket deadline and blocking I/O.
        server_socket.set_nonblocking(false)?;
        let close_client = client_socket.try_clone()?;
        let close_server = server_socket.try_clone()?;
        let server_tls = Arc::clone(&self.server_tls);
        let service = Arc::clone(service);
        let settings = consistency::Settings::checked(None, None, missing_forward)?;
        let thread = std::thread::Builder::new()
            .name("formal-api-tls".into())
            .spawn(move || {
                let _scope = RequestDeadlineScope::enter(deadline);
                let connection =
                    rustls::ServerConnection::new(server_tls).map_err(io::Error::other)?;
                let mut stream = StreamOwned::new(
                    connection,
                    DeadlineStream {
                        stream: server_socket,
                        deadline,
                    },
                );
                stream.sock.deadline =
                    execution_deadline_with_response_reserve(Instant::now(), deadline);
                let budget = stream
                    .sock
                    .deadline
                    .saturating_duration_since(Instant::now());
                let parsed = read_request_with_ui(&mut stream, budget, true, false);
                stream.sock.deadline = deadline;
                if stream.conn.alpn_protocol() != Some(b"http/1.1".as_slice()) {
                    return Err(io::Error::other("formal API ALPN changed"));
                }
                let attempt = crypto::random::<16>()
                    .map_err(|_| io::Error::other("formal API ingress randomness unavailable"))?;
                let client_certificates = stream.conn.peer_certificates().map(|certificates| {
                    certificates
                        .iter()
                        .map(|certificate| certificate.as_ref().to_vec())
                        .collect()
                });
                let (reply, head, namespace) = process_parsed_request(
                    &service,
                    None,
                    parsed,
                    &mut stream,
                    client_certificates,
                    peer.ip(),
                    &attempt,
                    settings,
                    deadline,
                );
                let redirect = matches!(&reply, snapshot::NativeReply::Redirect { .. });
                write_http1_reply(&mut stream, reply, head, &namespace, deadline);
                if redirect {
                    snapshot::finish_redirect_connection(&mut stream);
                }
                Ok(())
            })?;
        let worker = RequestWorker {
            thread: Some(thread),
            client: close_client,
            server: close_server,
        };
        let connection = rustls::ClientConnection::new(
            Arc::clone(&self.client_tls),
            rustls::pki_types::ServerName::try_from("localhost".to_owned())?,
        )?;
        let mut client = StreamOwned::new(
            connection,
            DeadlineStream {
                stream: client_socket,
                deadline,
            },
        );
        client.write_all(request)?;
        client.flush()?;
        if client.conn.alpn_protocol() != Some(b"http/1.1".as_slice())
            || client
                .conn
                .peer_certificates()
                .and_then(|chain| chain.first())
                .is_none_or(|leaf| leaf.as_ref() != self.expected_leaf.as_slice())
        {
            return Err("formal API authenticated peer or ALPN changed".into());
        }
        let mut output = Zeroizing::new(Vec::new());
        let mut byte = [0u8; 1];
        while !output.ends_with(b"\r\n\r\n") {
            if output.len() >= 64 * 1024 {
                return Err("formal API response header bound".into());
            }
            remaining()?;
            client.read_exact(&mut byte)?;
            output.push(byte[0]);
        }
        let headers = std::str::from_utf8(&output)?;
        let mut lines = headers[..headers.len() - 4].split("\r\n");
        let status = lines.next().ok_or("formal API response status absent")?;
        if !status.starts_with("HTTP/1.1 ") {
            return Err("formal API response status malformed".into());
        }
        let status_code: u16 = status
            .split(' ')
            .nth(1)
            .ok_or("formal API response status malformed")?
            .parse()?;
        let mut content_length = None;
        for line in lines {
            let (name, value) = line.split_once(':').ok_or("formal API header framing")?;
            if name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return Err("formal API duplicate content length".into());
                }
                content_length = Some(value.trim().parse::<usize>()?);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(
                    "formal API component requires explicit complete response length".into(),
                );
            }
        }
        let body_length = match content_length {
            Some(_) if request.starts_with(b"HEAD ") => 0,
            Some(length) => length,
            None if status_code == 204 => 0,
            None => return Err("formal API response content length absent".into()),
        };
        let bound = usize::try_from(crate::snapshot_file::MAX_NATIVE_ARCHIVE)?;
        if body_length > bound {
            return Err("formal API response archive bound".into());
        }
        let header_length = output.len();
        output.resize(
            header_length
                .checked_add(body_length)
                .ok_or("formal API length overflow")?,
            0,
        );
        client.read_exact(&mut output[header_length..])?;
        remaining()?;
        // The complete Content-Length response is already owned. Close the
        // actual socket before joining the 307 response-side drain; a cloned
        // cleanup descriptor must not keep that drain open until the deadline.
        client.conn.send_close_notify();
        let _ = client.flush();
        let _ = client.sock.stream.shutdown(Shutdown::Both);
        drop(client);
        worker.join()?;
        remaining()?;
        Ok(output)
    }
}
