//! Public KV2 duration strings follow OpenBao's Go time.Duration rendering.
//! This response formatter never changes the stored seconds/nanoseconds or the
//! canonical seconds strings used by lossless import/export and raw recovery.

pub(super) fn display(seconds: u64, nanos: u32) -> String {
    if seconds == 0 {
        if nanos == 0 {
            return "0s".into();
        }
        if nanos < 1_000 {
            return format!("{nanos}ns");
        }
        let (scale, width, unit) = if nanos < 1_000_000 {
            (1_000, 3, "µs")
        } else {
            (1_000_000, 6, "ms")
        };
        let whole = nanos / scale;
        let fraction = nanos % scale;
        return if fraction == 0 {
            format!("{whole}{unit}")
        } else {
            let fraction = format!("{fraction:0width$}");
            format!("{whole}.{}{unit}", fraction.trim_end_matches('0'))
        };
    }
    let fraction = if nanos == 0 {
        String::new()
    } else {
        let fraction = format!("{nanos:09}");
        format!(".{}", fraction.trim_end_matches('0'))
    };
    let trailing_seconds = seconds % 60;
    if seconds >= 3_600 {
        let hours = seconds / 3_600;
        let minutes = (seconds / 60) % 60;
        format!("{hours}h{minutes}m{trailing_seconds}{fraction}s")
    } else if seconds >= 60 {
        let minutes = seconds / 60;
        format!("{minutes}m{trailing_seconds}{fraction}s")
    } else {
        format!("{seconds}{fraction}s")
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::display;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn wire_duration_matches_go_unit_boundaries_and_exact_fractions() {
        for (seconds, nanos, expected) in [
            (0, 0, "0s"),
            (0, 1, "1ns"),
            (0, 113, "113ns"),
            (0, 999, "999ns"),
            (0, 1_000, "1µs"),
            (0, 1_001, "1.001µs"),
            (0, 123_400, "123.4µs"),
            (0, 999_999, "999.999µs"),
            (0, 1_000_000, "1ms"),
            (0, 1_000_001, "1.000001ms"),
            (0, 500_000_000, "500ms"),
            (0, 999_999_999, "999.999999ms"),
            (1, 0, "1s"),
            (1, 1, "1.000000001s"),
            (59, 999_999_999, "59.999999999s"),
            (60, 0, "1m0s"),
            (60, 1, "1m0.000000001s"),
            (61, 500_000_000, "1m1.5s"),
            (3_599, 0, "59m59s"),
            (3_600, 0, "1h0m0s"),
            (3_601, 1, "1h0m1.000000001s"),
            (7_200, 500_000_000, "2h0m0.5s"),
            (86_400, 0, "24h0m0s"),
            (259_380, 500_000_000, "72h3m0.5s"),
            (315_360_000, 0, "87600h0m0s"),
        ] {
            assert_eq!(display(seconds, nanos), expected, "{seconds}s + {nanos}ns");
        }
    }

    #[test]
    fn wire_duration_public_config_and_metadata_survive_cold_reopen() -> TestResult {
        let mut owner = Kv2::default();
        owner.handle(
            "POST",
            "config",
            &json!({"delete_version_after":"86400s"}),
            100,
        )?;
        owner.handle(
            "POST",
            "metadata/future",
            &json!({"delete_version_after":"86400s"}),
            100,
        )?;
        owner.handle("POST", "data/future", &json!({"data":{"value":true}}), 100)?;
        let bytes = serde_json::to_vec(&owner)?;
        let reopened: Kv2 = serde_json::from_slice(&bytes)?;
        for engine in [&owner, &reopened] {
            for path in ["config", "metadata/future"] {
                let response = engine.handle_read("GET", path, &json!({}), 101)?;
                assert_eq!(response.status, 200);
                assert_eq!(response.body["data"]["delete_version_after"], "24h0m0s");
            }
            assert_eq!(serde_json::to_vec(engine)?, bytes);
            assert_eq!(engine.config.delete_version_after, 86_400);
            assert_eq!(engine.config.delete_version_after_nanos, 0);
        }
        Ok(())
    }

    #[test]
    fn wire_duration_imported_precision_changes_only_public_responses() -> TestResult {
        let input = json!({
            "schema":lossless::IMPORT_SCHEMA,
            "config":{"max_versions":3,"cas_required":false,"metadata_cas_required":false,
                      "delete_version_after":"0.000000113s"},
            "entries":{"future":{
                "created_time":"1970-01-01T00:01:40Z","updated_time":"1970-01-01T00:01:40Z",
                "current_version":1,"oldest_version":0,"current_metadata_version":0,
                "max_versions":3,"cas_required":false,"metadata_cas_required":false,
                "delete_version_after":"7200.5s","custom_metadata":null,
                "versions":{"1":{"created_time":"1970-01-01T00:01:40Z","deletion_time":"",
                    "destroyed":false,"source_deletion_time":"","data":{"value":true}}}
            }}
        });
        let owner = Kv2::from_lossless_import_json(&serde_json::to_vec(&input)?)?;
        let before = serde_json::to_vec(&owner)?;
        let reopened: Kv2 = serde_json::from_slice(&before)?;
        reopened.validate_lossless_state()?;
        assert_eq!(
            reopened.handle_read("GET", "config", &json!({}), 101)?.body["data"]["delete_version_after"],
            "113ns"
        );
        assert_eq!(
            reopened
                .handle_read("GET", "metadata/future", &json!({}), 101)?
                .body["data"]["delete_version_after"],
            "2h0m0.5s"
        );
        assert_eq!(serde_json::to_vec(&reopened)?, before);
        assert_eq!(lossless::display_duration(0, 113), "0.000000113s");
        assert_eq!(lossless::display_duration(7_200, 500_000_000), "7200.5s");
        Ok(())
    }
}
