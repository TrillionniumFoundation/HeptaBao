use super::*;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn selected(value: Value) -> Result<Headers, &'static str> {
    let names = value
        .as_object()
        .ok_or("object")?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    Headers::from_sdk(Some(&value), &names).map_err(|()| "bounded headers")
}

#[test]
fn numeric_quota_merge_replaces_only_its_names_and_preserves_logical_metadata() -> TestResult {
    let mut headers = selected(json!({"X-Logical":["retained"],"Retry-After":["old","older"]}))?;
    headers
        .merge_quota(selected(
            json!({"Retry-After":["5"],"X-RateLimit-Limit":["2"]}),
        )?)
        .map_err(|()| "quota merge")?;
    assert_eq!(
        serde_json::to_value(&headers)?,
        json!({
            "X-Logical":["retained"], "Retry-After":["5"], "X-Ratelimit-Limit":["2"],
        })
    );
    Ok(())
}

#[test]
fn invalid_quota_metadata_cannot_modify_logical_headers() -> TestResult {
    for invalid in [
        json!({"X-Logical":["injected"]}),
        json!({"Retry-After":["1","2"]}),
        json!({"Retry-After":["-1"]}),
        json!({"Retry-After":[""]}),
    ] {
        let mut headers = selected(json!({"X-Logical":["retained"]}))?;
        assert!(headers.merge_quota(selected(invalid)?).is_err());
        assert_eq!(
            serde_json::to_value(&headers)?,
            json!({"X-Logical":["retained"]})
        );
    }
    Ok(())
}

#[test]
fn quota_merge_obeys_name_and_byte_bounds_atomically() -> TestResult {
    let names: serde_json::Map<String, Value> = (0..64)
        .map(|index| (format!("X-Field-{index}"), json!(["value"])))
        .collect();
    let bytes = json!({"X-Blob": vec!["a".repeat(4080); 8]});
    for value in [Value::Object(names), bytes] {
        let mut headers = selected(value)?;
        let before = serde_json::to_value(&headers)?;
        let quota = selected(json!({"Retry-After":["3599"],"X-RateLimit-Limit":["10"],
            "X-RateLimit-Remaining":["0"],"X-RateLimit-Reset":["3599"]}))?;
        assert!(headers.merge_quota(quota).is_err());
        assert_eq!(serde_json::to_value(&headers)?, before);
    }
    Ok(())
}
