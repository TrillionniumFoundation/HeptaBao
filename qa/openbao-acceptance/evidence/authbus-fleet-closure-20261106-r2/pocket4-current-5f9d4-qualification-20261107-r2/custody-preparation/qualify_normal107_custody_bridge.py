"""Bounded real Linux children for the new custody bridge, never Rust or product tests."""
import ast
import json
import os
from pathlib import Path
import signal
import sys
import time


def qualify(bridge, custody, controller_source, directory, outcomes=None):
    began = time.monotonic()
    deadline = began + 30
    syscall_events = []
    signal_probe = None
    def audit(event, args):
        nonlocal signal_probe
        if event == 'heptabao.qualification.signal_probe_begin':
            if signal_probe is not None or args not in (('post_wait',), ('unknown_group',)):
                raise RuntimeError('invalid_local_signal_probe_begin')
            signal_probe = args[0]
        elif event == 'heptabao.qualification.signal_probe_end':
            if args != (signal_probe,) or signal_probe is None:
                raise RuntimeError('invalid_local_signal_probe_end')
            signal_probe = None
        if event in ('os.killpg', 'os.kill'):
            syscall_events.append({'event': event, 'target': args[0], 'signal': int(args[1]),
                                   'probe_guard_blocked_before_kernel': signal_probe is not None})
            if signal_probe is not None:
                raise RuntimeError('invalid_signal_probe_blocked_before_kernel')
    sys.addaudithook(audit)
    selected = {'Failed', 'need', 'process_group', 'clean_owned_group', 'digest',
                'publish', 'checkpoint', 'run_step'}
    nodes = ast.parse(controller_source).body
    pieces = [ast.get_source_segment(controller_source, node) for node in nodes
              if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in selected]
    if len(pieces) != len(selected):
        raise RuntimeError('exact_original_controller_functions_required')
    original_functions = '\n\n'.join(pieces)
    if outcomes is None:
        outcomes = []
    elif type(outcomes) is not list or outcomes:
        raise RuntimeError('new_empty_outcome_list_required')
    variants = [
        ('closed_success', "run_step('actual', [sys.executable, '-I', '-S', '-B', '-c', 'print(1)'], 2)\nraise SystemExit(0)\n", True),
        ('timeout_rejected', "try:\n    run_step('actual', [sys.executable, '-I', '-S', '-B', '-c', 'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(10)'], .2)\nexcept Failed:\n    raise SystemExit(1)\nraise SystemExit(0)\n", False),
        ('post_wait_signal_rejected_without_syscall', "run_step('actual', [sys.executable, '-I', '-S', '-B', '-c', 'print(1)'], 2)\nsys.audit('heptabao.qualification.signal_probe_begin','post_wait')\ntry:\n    os.killpg(REPORT['steps'][-1]['pid'], signal.SIGTERM)\nfinally:\n    sys.audit('heptabao.qualification.signal_probe_end','post_wait')\nraise SystemExit(0)\n", False),
        ('unknown_group_rejected_without_syscall', "run_step('actual', [sys.executable, '-I', '-S', '-B', '-c', 'print(1)'], 2)\nsys.audit('heptabao.qualification.signal_probe_begin','unknown_group')\ntry:\n    os.killpg(2147483647, signal.SIGTERM)\nfinally:\n    sys.audit('heptabao.qualification.signal_probe_end','unknown_group')\nraise SystemExit(0)\n", False),
        ('inner_zero_with_live_original_rejected', "subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', 'import time;time.sleep(10)'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)\nraise SystemExit(0)\n", False),
    ]
    for name, body, expected_pass in variants:
        if time.monotonic() >= deadline - 6:
            raise RuntimeError('qualification_original_deadline')
        root = directory / name
        root.mkdir(mode=0o700)
        prologue = ('import hashlib,json,os,re,signal,subprocess,sys,time\nfrom pathlib import Path\n'
                    + 'OUT=Path(' + repr(str(root)) + ');SOURCE=OUT\n'
                    + "ENV={'PATH':'/usr/bin:/bin'};REPORT={'steps':[]}\n"
                    + 'START=time.monotonic();DEADLINE=START+38\n')
        text = prologue + original_functions + '\n\n' + body
        first = len(syscall_events)
        result, namespace = bridge.execute('RUN_CURRENT_CONTROLLER()\n', str(root/'admission.fixture.py'),
                                           text, str(root/'controller.fixture.py'), custody,
                                           deadline=min(deadline, time.monotonic()+8))
        observed = syscall_events[first:]
        receipt = result['process_custody']
        children = receipt['children']
        safe_closed = (len(children) == 1 and result['originals_closed']
                       and not result['remote_closure_unknown']
                       and children[0]['original_wait_count'] == 1
                       and children[0]['original_wait_completed']
                       and children[0]['no_live_members_before_reap'])
        correct = (result['passed_controller_exit_and_custody'] is expected_pass
                   and safe_closed and signal_probe is None)
        if name in ('post_wait_signal_rejected_without_syscall', 'unknown_group_rejected_without_syscall'):
            correct = correct and not observed and receipt['failed'] is True
        if name == 'post_wait_signal_rejected_without_syscall':
            correct = correct and any(x.get('outcome') == 'already_retired_no_signal'
                                      and x.get('group_signal_sent') is False for x in receipt['controls'])
        if name == 'unknown_group_rejected_without_syscall':
            correct = correct and any(x.get('outcome') == 'refused_unknown_original'
                                      for x in receipt['controls'])
        if name == 'timeout_rejected':
            steps = namespace['REPORT']['steps']
            correct = correct and len(steps) == 1 and steps[0]['timed_out'] is True
            correct = correct and bool(observed) and all(x['target'] == children[0]['pid'] for x in observed)
        if name == 'inner_zero_with_live_original_rejected':
            correct = correct and result['controller_native_exit_code'] == 0 and receipt['failed'] is True
        outcomes.append({'name': name, 'passed': bool(correct), 'expected_campaign_accepted': expected_pass,
                         'native_signal_syscalls': observed, 'observation': result})
        if not correct:
            raise RuntimeError('real_child_qualification_failed_' + name)
    if time.monotonic() >= deadline:
        raise RuntimeError('qualification_original_deadline_after_closure')
    return {'schema': 'heptabao.linux-normal107-custody-bridge-real-child-qualification.v1',
            'status': 'passed', 'platform': sys.platform, 'cases': outcomes,
            'passed_cases': len(outcomes), 'expected_cases': 5,
            'all_originals_closed': all(x['observation']['originals_closed'] for x in outcomes),
            'rust_build_executed': False, 'product_binary_executions': 0,
            'normal107_qualified': False, 'elapsed_seconds': time.monotonic()-began,
            'all_selected_original_functions_copied_verbatim': True}
