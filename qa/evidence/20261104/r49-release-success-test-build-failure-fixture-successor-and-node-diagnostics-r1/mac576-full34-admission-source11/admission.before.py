def normal61_admission():
 need(BINDING_READY is True,'normal61_and_local_prerequisite_bindings_unresolved')
 need(all(isinstance(x,str) and len(x)==64 and all(c in '0123456789abcdef' for c in x)
          for x in (NORMAL61_SHA,NORMAL_NATIVE_SHA,NORMAL_RELEASE_SHA)),
      'exact_actual_provenance_pins_required')
 actual=PRODUCT/'result.public.json'
 need(sha(actual)==NORMAL61_SHA,'combined_normal61_whole_pin')
 n=json.loads(actual.read_bytes())
 need(n.get('schema')=='heptabao.mac-normal-same-root-publication-exact-tests.v1'
      and n.get('source_commit')==HEAD and n.get('source_tree')==TREE
      and n.get('controller_sha256')=='3e013354f125cc4c282905beb6347d19f84448a14c304efd576b4d8705e0c2d8'
      and n.get('status')=='passed' and n.get('test_count')==44
      and n.get('selected_test_total')==61 and n.get('normal_default_features') is True
      and n.get('fixture_features')==[] and n.get('original_44_status')=='passed'
      and n.get('original_44_and_ingress_7_status')=='passed'
      and n.get('original_60_status')=='passed' and n.get('original_60_test_total')==60
      and n.get('additional_test_counts')=={'ingress_observer':7,'cold_h2':9,'same_root_publication':1}
      and n.get('source_unchanged') is True and n.get('binary_unchanged') is True
      and n.get('release_artifacts_unchanged') is True,'exact_normal61_qualification')
 for key,names in (
     ('ingress_observer_regression',["service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_permission_is_affine_and_resumed_binding_never_arms","service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_permission_rejects_actual_new_request_nonce_or_selected_root","service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_actual_failed_repair_closes_reselection_before_any_result","ha::native_v6_runtime::request_timing_tests::native_request_timing_failure_has_only_bounded_static_metadata","ha::native_v6_runtime::request_timing_tests::native_request_timing_sixty_four_buckets_preserve_existing_aggregates","ha::native_v6_runtime::request_timing_tests::native_request_timing_observes_deadlines_but_preserves_once_only_results","ha::native_v6_runtime::request_timing_tests::native_request_timing_phase_advance_is_distinct_from_operation_success"]),
     ('cold_h2_regression',["service::native_v6_ha_install::read::cold_timing_tests::cold_native_ha_timing_preserves_once_and_owned_result_identity","service::native_v6_ha_install::read::cold_timing_tests::cold_native_ha_timing_preserves_nested_source_and_inner_results","service::native_v6_ha_install::tests::native_ha_install_batches_actual_readindex_cold_missing_and_corrupt_file","http::h2_transport::sync_worker_tests::h2_sync_worker_is_unentered_and_retains_outer_context","http::h2_transport::sync_worker_tests::h2_sync_worker_expired_deadline_never_calls_work","http::h2_transport::sync_worker_tests::h2_sync_worker_preserves_inner_result","http::h2_transport::sync_worker_tests::h2_sync_worker_joins_panicked_work_and_drops_capture","http::h2_transport::sync_worker_tests::h2_sync_worker_does_not_authorize_nested_runtime_context","http::h2_transport::sync_worker_tests::h2_sync_worker_cancelled_waiter_retains_blocking_capacity"])):
  group=n.get(key,{})
  need(group.get('status')=='passed' and group.get('test_count')==len(names)
       and group.get('actual_test_names')==names and group.get('clamped_to_original_outer_deadline') is True,
       'exact_separate_normal_regression')
 same=n.get('same_root_publication_regression',{})
 need(same.get('schema')=='heptabao.normal-same-root-publication-regression.v1'
      and same.get('status')=='passed' and same.get('test_count')==1
      and same.get('actual_test_names')==['service::native_v6_ha_install::tests::same_root_republication_tests::native_ha_same_root_republication_advances_warm_and_cold_cursors']
      and same.get('original_44_7_9_denominators_unchanged') is True
      and same.get('clamped_to_original_outer_deadline') is True
      and same.get('new_total_group_cap_seconds')==600,
      'independent_same_root_publication_regression')
 cleanup=n.get('cleanup')
 need(isinstance(cleanup,list) and cleanup and all(
      row.get('exit_code')==0 and row.get('direct_child_reaped') is True
      and row.get('remaining')==[] and not row.get('cleanup_error_type') for row in cleanup),
      'normal_all_children_terminal')
 return NORMAL61_SHA

