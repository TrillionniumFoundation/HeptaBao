"""Keep the unchanged Linux campaign under original-child process custody.

The caller pins all sources. This module grants no storage or service authority.
The admission callback is invoked once; the original controller is compiled and
executed verbatim. Its SystemExit is caught inside the existing custody context
so an exit code of zero cannot conceal unfinished children or a custody gap.
"""
import time


def execute(admission_source, admission_filename, controller_source,
            controller_filename, custody, *, deadline):
    namespace = None
    owner = None
    called = 0
    exit_code = None
    exception_type = None

    def run_controller():
        nonlocal namespace, called, exit_code, exception_type
        called += 1
        if called != 1 or time.monotonic() >= deadline:
            raise RuntimeError('single_controller_before_original_deadline_required')
        namespace = {'__name__': '__main__', '__file__': controller_filename}
        try:
            exec(compile(controller_source, controller_filename, 'exec'), namespace)
        except SystemExit as error:
            exit_code = 0 if error.code is None else error.code
        except BaseException as error:
            exception_type = type(error).__name__
        else:
            exception_type = 'MissingOriginalSystemExit'

    try:
        with custody.activated() as current:
            owner = current
            admission = {'__name__': '__main__', '__file__': admission_filename,
                         'RUN_CURRENT_CONTROLLER': run_controller}
            exec(compile(admission_source, admission_filename, 'exec'), admission)
            if called != 1:
                raise RuntimeError('admission_did_not_invoke_one_controller')
            current.assert_retired()
    except BaseException as error:
        exception_type = exception_type or type(error).__name__
    receipt = None if owner is None else owner.receipt()
    closed = receipt is not None and receipt.get('finished') is True and all(
        row.get('original_wait_count') == 1
        and row.get('original_wait_completed') is True
        and row.get('no_live_members_before_reap') is True
        for row in receipt.get('children', []))
    passed = (called == 1 and type(exit_code) is int and exit_code == 0
              and exception_type is None and closed
              and receipt.get('passed_process_custody') is True
              and time.monotonic() < deadline)
    observation = {
        'schema': 'heptabao.normal107-original-controller-custody.v1',
        'controller_invocations': called, 'controller_native_exit_code':
            exit_code if type(exit_code) is int else None,
        'exception_type': exception_type, 'process_custody': receipt,
        'originals_closed': closed, 'remote_closure_unknown': not closed,
        'passed_controller_exit_and_custody': passed,
        'controller_result_validation_required_separately': True,
        'controller_functions_or_workload_modified': False,
        'deadline_renewed': False,
    }
    return observation, namespace


def require_current_result(value, selection, commit, tree):
    """Bind the independently read original result to the full selected cohort."""
    groups = selection['legacy_groups'] + selection['legacy_additional_groups'] + selection['added_groups']
    names = [name for group in groups for name in group['tests']]
    if (selection['execution_source_commit'] != commit
            or selection['execution_source_tree'] != tree
            or len(names) != 107 or len(set(names)) != 107
            or value.get('schema') != 'heptabao.convergence-normal-build-tests.v1'
            or value.get('status') != 'passed' or value.get('failure') is not None
            or value.get('source_commit') != commit or value.get('source_tree') != tree
            or value.get('passed_cases') != 107 or value.get('executed_passed_cases') != 107
            or value.get('not_qualified_cases') != 0
            or value.get('source_and_artifacts_unchanged') is not True
            or value.get('outer_budget_seconds') != 12000
            or value.get('deadline_renewed') is not False
            or value.get('build_environment_overrides') != selection['original_build']['env']
            or value.get('expected_denominators') != selection['denominators']):
        raise RuntimeError('exact_current_normal107_result_required')
    actual = value.get('groups')
    if type(actual) is not list or len(actual) != len(groups):
        raise RuntimeError('complete_original_groups_required')
    for expected, row in zip(groups, actual):
        enumeration = value.get('enumeration', {}).get(expected['label'], {})
        if (row.get('label') != expected['label'] or row.get('status') != 'passed'
                or row.get('crate') != expected['crate']
                or row.get('tests') != expected['tests']
                or row.get('expected_count') != expected['expected_count']
                or row.get('passed') != expected['expected_count']
                or row.get('original_group_budget_seconds') != expected['runtime_seconds']
                or row.get('budget_renewed_per_case') is not False
                or enumeration.get('matched_count') != expected['expected_count']
                or enumeration.get('matched_names') != sorted(expected['tests'])
                or type(row.get('results')) is not list or not row['results']):
            raise RuntimeError('complete_exact_original_group_results_required')
        suffixes = expected.get('argv_suffixes', [expected.get('argv_suffix')])
        per_result = 1 if len(suffixes) > 1 or expected.get('selection_mode') == 'per-test-exact' else expected['expected_count']
        if len(row['results']) != len(suffixes):
            raise RuntimeError('all_exact_original_invocations_required')
        for result in row['results']:
            if (result.get('exact_denominator_passed') is not True
                    or result.get('reported_state') != 'ok'
                    or any(type(result.get(k)) is not int for k in
                           ('passed', 'failed', 'ignored', 'measured', 'filtered_out'))
                    or result['passed'] != per_result
                    or any(result[k] != 0 for k in ('failed', 'ignored', 'measured'))
                    or result['filtered_out'] < 0):
                raise RuntimeError('no_failed_ignored_measured_or_missing_cases')
    steps = value.get('steps')
    if type(steps) is not list or not steps or any(
            step.get('exit_code') != 0 or step.get('timed_out') is not False
            or 'exception_type' in step
            or step.get('owned_group_cleanup', {}).get('all_owned_processes_gone') is not True
            or step.get('unexpected_live_descendants_on_success') is True for step in steps):
        raise RuntimeError('all_original_steps_and_group_closures_required')
    for when in ('old_retained_artifacts_before', 'old_retained_artifacts_after'):
        observed = value.get(when)
        if type(observed) is not dict or set(observed) != set(selection['old_retained_artifacts']):
            raise RuntimeError('complete_retained_input_map_required')
        if any(row.get('matches_original') is not True for row in observed.values()):
            raise RuntimeError('all_retained_inputs_unchanged_required')
    return True
