//! Normal Raft storage and the same original 15-second request budget.
//! Child negative reads use actual forwarding, committed ReadIndex and cold
//! persisted state; these component tests do not replace physical-host HA.
use super::*;

fn scoped(
    pipeline: &MissingRoutePipeline,
    index: usize,
    namespace: &str,
    method: &str,
    path: &str,
    body: Value,
) -> TestResult<Response> {
    pipeline.with_service_mut_for_delivery_test(index, |service| {
        Ok(service.handle(method, path, namespace, pipeline.admin(), body))
    })
}

#[test]
fn native_missing_route_formal_ha_child_retirement_readindex_forwarding_and_cold() -> TestResult {
    let mut pipeline = MissingRoutePipeline::start()?;
    let first = pipeline.ready_leader()?;
    let standby = (first + 1) % 3;
    expect(
        scoped(
            &pipeline,
            standby,
            "",
            "POST",
            "sys/namespaces/team",
            json!({}),
        )?,
        200,
        "formal HA parent namespace",
    )?;
    expect(
        scoped(
            &pipeline,
            standby,
            "team",
            "POST",
            "sys/namespaces/child",
            json!({}),
        )?,
        200,
        "formal HA child namespace",
    )?;
    let before = selection(&pipeline, first)?;
    for index in 0..3 {
        // The same prefix is a real, still readable root KV2 mount.
        negative(scoped(
            &pipeline,
            index,
            "team/child",
            "GET",
            "secret/data/pipeline/history",
            json!({}),
        )?)?;
        assert_eq!(selection(&pipeline, index)?, before);
        pipeline.assert_history(index, &[(1, "seed-v5")])?;
    }
    expect(
        scoped(
            &pipeline,
            standby,
            "team/child",
            "POST",
            "sys/mounts/retired",
            json!({"type":"kv","options":{"version":"1"}}),
        )?,
        204,
        "formal HA actual child KV1 mount",
    )?;
    expect(
        scoped(
            &pipeline,
            standby,
            "team/child",
            "POST",
            "retired/value",
            json!({"owner":"child"}),
        )?,
        204,
        "formal HA child value",
    )?;
    let read = expect(
        scoped(
            &pipeline,
            standby,
            "team/child",
            "GET",
            "retired/value",
            json!({}),
        )?,
        200,
        "formal HA child mounted read",
    )?;
    assert_eq!(read.body["data"], json!({"owner":"child"}));
    expect(
        scoped(
            &pipeline,
            standby,
            "team/child",
            "DELETE",
            "sys/mounts/retired",
            json!({}),
        )?,
        204,
        "formal HA actual child retirement",
    )?;
    let retired = selection(&pipeline, first)?;
    assert!(retired.0 > before.0 && retired.2 > before.2 && retired.1 != before.1);
    for index in 0..3 {
        negative(scoped(
            &pipeline,
            index,
            "team/child",
            "GET",
            "retired/value",
            json!({}),
        )?)?;
        assert_eq!(selection(&pipeline, index)?, retired);
    }
    pipeline.stop_process(first)?;
    let next = pipeline.ready_leader()?;
    assert_ne!(first, next);
    negative(scoped(
        &pipeline,
        next,
        "team/child",
        "LIST",
        "retired/value",
        json!({}),
    )?)?;
    assert_eq!(selection(&pipeline, next)?, retired);
    pipeline.start_formal_process(first)?;
    pipeline.wait_cold_native_readindex_ready(first)?;
    pipeline.unseal(first)?;
    negative(scoped(
        &pipeline,
        first,
        "team/child",
        "GET",
        "retired/value",
        json!({}),
    )?)?;
    assert_eq!(selection(&pipeline, first)?, retired);
    pipeline.assert_history(first, &[(1, "seed-v5")])?;
    Ok(())
}
