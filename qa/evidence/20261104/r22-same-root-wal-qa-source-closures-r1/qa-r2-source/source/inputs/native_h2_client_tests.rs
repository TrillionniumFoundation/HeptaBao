//! Components for the independent QA client. HTTP/2 I/O uses one owned
//! in-memory duplex per case, with no network, product or credential access.
use super::*;
use tokio::sync::oneshot;

#[derive(Clone, Copy, PartialEq)]
enum Ending { DataEos, EmptyTrailersEos, ResetZeroBeforeEos, EofBeforeEos, ShortEos }

async fn joined_cancel_or_clean<T>(task: tokio::task::JoinHandle<Checked<T>>) -> Checked<()> {
    match task.await {
        Err(error) if error.is_cancelled() => Ok(()),
        Ok(Ok(_)) => Ok(()),
        _ => Err("component_task_not_clean"),
    }
}

async fn exercise(ending: Ending) -> Checked<(Checked<()>, Observation, usize)> {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (consumed_tx, consumed_rx) = oneshot::channel::<()>();
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await
            .map_err(|_| "component_server_handshake")?;
        let (request, mut responder) = connection.accept().await
            .ok_or("component_one_request_missing")?
            .map_err(|_| "component_server_request")?;
        if request.method() != "GET" || request.uri().path() != "/owned" {
            return Err("component_one_request_shape");
        }
        let driver = tokio::spawn(async move {
            if connection.accept().await.is_some() {
                return Err("component_unexpected_second_request");
            }
            Ok(())
        });
        let operation = async {
            let response = http::Response::builder().status(200)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_LENGTH,
                        if ending == Ending::ShortEos { "3" } else { "2" })
                .body(()).map_err(|_| "component_response")?;
            let mut output = responder.send_response(response, false)
                .map_err(|_| "component_headers_send")?;
            output.send_data(Bytes::from_static(b"{}"),
                             ending == Ending::DataEos || ending == Ending::ShortEos)
                .map_err(|_| "component_data_send")?;
            match ending {
                Ending::EmptyTrailersEos => output.send_trailers(HeaderMap::new())
                    .map_err(|_| "component_trailers_send")?,
                Ending::ResetZeroBeforeEos => {
                    consumed_rx.await.map_err(|_| "component_consumption_ack")?;
                    output.send_reset(h2::Reason::NO_ERROR);
                }
                Ending::EofBeforeEos => {
                    consumed_rx.await.map_err(|_| "component_consumption_ack")?;
                    driver.abort();
                }
                _ => {}
            }
            // The negative reset/EOF is sent only after the client has received
            // the full declared two-byte body. No END_STREAM has been sent.
            done_rx.await.map_err(|_| "component_observation_ack")?;
            drop(output);
            drop(request);
            Ok(())
        }.await;
        driver.abort();
        let joined = joined_cancel_or_clean(driver).await;
        operation?;
        joined
    });

    let (mut sender, connection) = h2::client::handshake(client_io).await
        .map_err(|_| "component_client_handshake")?;
    let client_driver = tokio::spawn(async move {
        connection.await.map_err(|_| "component_client_driver")
    });
    let mut body = Zeroizing::new(Vec::new());
    let mut observation = Observation::default();
    let result = async {
        let request = Request::builder().method("GET").uri("https://localhost/owned")
            .version(Version::HTTP_2).body(()).map_err(|_| "component_request")?;
        let (response, send_stream) = sender.send_request(request, true)
            .map_err(|_| "component_send")?;
        if send_stream.stream_id().as_u32() != 1 {
            return Err("component_stream_id");
        }
        let response = response.await.map_err(|_| "component_response_headers")?;
        let expected = inspect_headers(response.headers(), &mut observation)?;
        let mut stream = response.into_body();
        if ending == Ending::ResetZeroBeforeEos || ending == Ending::EofBeforeEos {
            // Establish the exact regression boundary: all Content-Length bytes
            // are already delivered, but the receive half has not seen EOS.
            let first = stream.data().await.ok_or("component_first_data_missing")?
                .map_err(|_| "component_first_data")?;
            if first.as_ref() != b"{}" || expected != 2 || stream.is_end_stream() {
                return Err("component_no_eos_prerequisite");
            }
            body.extend_from_slice(&first);
            stream.flow_control().release_capacity(first.len())
                .map_err(|_| "component_release_capacity")?;
            observation.data_frames = 1;
            consumed_tx.send(()).map_err(|_| "component_consumption_ack_send")?;
        } else {
            drop(consumed_tx);
        }
        let received = receive_body(&mut stream, expected, &mut body, &mut observation).await;
        drop(stream);
        drop(send_stream);
        received
    }.await;
    let _ = done_tx.send(());
    drop(sender);
    client_driver.abort();
    // A deliberately malformed/aborted receive stream may also finish the
    // connection driver with its closed h2 error. This does not turn that
    // negative message into a success; the caller still checks the exact
    // receive result and response_complete remains false.
    match client_driver.await {
        Err(error) if error.is_cancelled() => {}
        Ok(Ok(())) => {}
        Ok(Err("component_client_driver"))
            if result.is_err() && matches!(ending, Ending::ResetZeroBeforeEos
                | Ending::EofBeforeEos | Ending::ShortEos) => {}
        _ => return Err("component_client_not_joined"),
    }
    match server.await {
        Ok(Ok(())) => {}
        _ => return Err("component_server_not_joined"),
    }
    Ok((result, observation, body.len()))
}

fn run_case(ending: Ending) -> Checked<(Checked<()>, Observation, usize)> {
    let runtime = Builder::new_current_thread().enable_all().build()
        .map_err(|_| "component_runtime")?;
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    let result = runtime.block_on(async { timeout_at(until, exercise(ending)).await })
        .map_err(|_| "component_deadline");
    drop(runtime);
    result?
}

#[test]
fn native_h2_client_accepts_complete_data_eos() -> Checked<()> {
    let (result, observation, bytes) = run_case(Ending::DataEos)?;
    result?;
    assert_eq!(bytes, 2);
    assert!(observation.data_none_observed && observation.trailers_completed
            && observation.trailers_empty && observation.recv_end_stream
            && observation.response_complete);
    Ok(())
}

#[test]
fn native_h2_client_accepts_complete_empty_trailers_eos() -> Checked<()> {
    let (result, observation, bytes) = run_case(Ending::EmptyTrailersEos)?;
    result?;
    assert_eq!(bytes, 2);
    assert!(observation.trailers_completed && observation.trailers_empty
            && observation.recv_end_stream && observation.response_complete);
    Ok(())
}

#[test]
fn native_h2_client_rejects_rst_no_error_after_exact_body_before_eos() -> Checked<()> {
    let (result, observation, bytes) = run_case(Ending::ResetZeroBeforeEos)?;
    assert_eq!(bytes, 2);
    assert_eq!(result, Err("h2_data_error"));
    assert!(!observation.response_complete && !observation.recv_end_stream);
    Ok(())
}

#[test]
fn native_h2_client_rejects_eof_after_exact_body_before_eos() -> Checked<()> {
    let (result, observation, bytes) = run_case(Ending::EofBeforeEos)?;
    assert_eq!(bytes, 2);
    assert_eq!(result, Err("h2_data_error"));
    assert!(!observation.response_complete && !observation.recv_end_stream);
    Ok(())
}

#[test]
fn native_h2_client_rejects_short_eos_and_duplicate_content_length() -> Checked<()> {
    let (result, observation, _) = run_case(Ending::ShortEos)?;
    assert!(result.is_err());
    assert!(!observation.response_complete);
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.append(header::CONTENT_LENGTH, HeaderValue::from_static("2"));
    headers.append(header::CONTENT_LENGTH, HeaderValue::from_static("2"));
    assert_eq!(inspect_headers(&headers, &mut Observation::default()),
               Err("single_content_length_required"));
    Ok(())
}

#[test]
fn native_h2_client_refuses_expired_or_extended_original_deadline() -> Checked<()> {
    let current = clock_ns()?;
    assert_eq!(deadline(current.saturating_sub(1)).err(), Some("original_deadline"));
    assert_eq!(deadline(current + HTTP_NS + 1_000_000_000).err(), Some("original_deadline"));
    Ok(())
}
