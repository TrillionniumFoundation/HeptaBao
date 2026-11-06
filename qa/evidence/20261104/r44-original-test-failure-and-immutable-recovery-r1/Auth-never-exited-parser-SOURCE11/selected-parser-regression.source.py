"""Selected-parser regression SOURCE; no imports or execution of product modules.
Interface: run_selected_parser_regression(before_source: str, after_source: str) -> dict.
Only the three AST definitions ManagerRefused/need/parse_print and the existing
consumer final-exit predicate are compiled from the supplied immutable public strings.
No host, filesystem, Native, SDK, service, credentials, sleep or retry.
"""
import ast
import copy
import re

def _selected(source):
    tree = ast.parse(source)
    names = {'ManagerRefused', 'need', 'parse_print'}
    selected = [copy.deepcopy(node) for node in tree.body
                if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in names]
    assert {node.name for node in selected} == names and len(selected) == 3
    scope = {'re': re}
    module = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
    exec(compile(module, '<selected-public-parser>', 'exec'), scope)
    predicates = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == 'need' and len(node.args) == 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == 'actual_launchd_phase_exit_zero'):
            predicates.append(copy.deepcopy(node.args[0]))
    assert len(predicates) == 1
    predicate = compile(ast.fix_missing_locations(ast.Expression(predicates[0])),
                        '<original-consumer-exit-predicate>', 'eval')
    return scope, predicate

def run_selected_parser_regression(before_source, after_source):
    old, old_final = _selected(before_source)
    new, new_final = _selected(after_source)
    target = 'gui/501/org.heptabao.qa.selected-parser-fixture'
    def raw(exit_value, pid='32527', runs='1', duplicate=False):
        lines = [target+' = {', '    path = /known/public-fixture.plist',
                 '    program = /known/python', '    arguments = {', '        /known/python',
                 '    }', '    state = running']
        if pid is not None:
            lines.append('    pid = '+pid)
        if runs is not None:
            lines.append('    runs = '+runs)
        if exit_value is not None:
            lines.append('    last exit code = '+exit_value)
            if duplicate:
                lines.append('    last exit code = '+exit_value)
        lines.append('}')
        return ('\n'.join(lines)+'\n').encode('ascii')
    outcomes = []
    def parse_or_code(scope, body):
        try:
            return {'kind': 'parsed', 'fields': scope['parse_print'](body, target)}
        except scope['ManagerRefused'] as error:
            return {'kind': 'refused', 'code': str(error)}
    def check(name, condition):
        assert condition, name
        outcomes.append({'name': name, 'passed': True})
    before = parse_or_code(old, raw('(never exited)'))
    after = parse_or_code(new, raw('(never exited)'))
    check('old_exact_observed_literal_refuses', before == {'kind': 'refused', 'code': 'typed_launchctl_integer'})
    check('new_exact_literal_is_explicit_none', after['kind'] == 'parsed' and 'last exit code' in after['fields']
          and after['fields']['last exit code'] is None)
    check('new_literal_keeps_pid_runs', after['fields']['pid'] == 32527 and after['fields']['runs'] == 1)
    check('original_consumer_does_not_accept_none', eval(new_final, {}, {'state': after['fields']}) is False)
    for value, expected in [('0', 0), ('78: EX_CONFIG', 78), ('-9', -9), ('1', 1)]:
        a = parse_or_code(old, raw(value))
        b = parse_or_code(new, raw(value))
        check('numeric_or_existing_symbol_'+value, a == b and b['kind'] == 'parsed'
              and type(b['fields']['last exit code']) is int
              and b['fields']['last exit code'] == expected)
        check('unchanged_consumer_'+value, eval(old_final, {}, {'state': a['fields']})
              == eval(new_final, {}, {'state': b['fields']}) == (expected == 0))
    for value in ['(Never exited)', 'never exited', '0: UNKNOWN', '78: EX_CONFIG unexpected']:
        a = parse_or_code(old, raw(value))
        b = parse_or_code(new, raw(value))
        check('unknown_exit_still_refused_'+value, a == b
              == {'kind': 'refused', 'code': 'typed_launchctl_integer'})
    for name, body, expected in [
            ('pid_literal', raw('(never exited)', pid='(never exited)'), 'typed_launchctl_integer'),
            ('runs_literal', raw('(never exited)', runs='(never exited)'), 'typed_launchctl_integer'),
            ('pid_zero', raw('(never exited)', pid='0'), 'actual_launchctl_pid'),
            ('duplicate_exit', raw('(never exited)', duplicate=True), 'unique_launchctl_field')]:
        check(name, parse_or_code(new, body) == {'kind': 'refused', 'code': expected})
    no_exit = parse_or_code(new, raw(None, pid=None))
    check('absent_exit_keeps_absent', no_exit['kind'] == 'parsed'
          and 'last exit code' not in no_exit['fields']
          and eval(new_final, {}, {'state': no_exit['fields']}) is False)
    no_pid = parse_or_code(new, raw('(never exited)', pid=None))
    check('sentinel_without_pid_is_not_consumer_success', no_pid['kind'] == 'parsed'
          and no_pid['fields']['last exit code'] is None
          and eval(new_final, {}, {'state': no_pid['fields']}) is False)
    return {'schema': 'heptabao.selected-launchctl-parser-regression.v1',
            'passed': True, 'checks': outcomes, 'count': len(outcomes),
            'productModulesExecuted': False, 'nativeCalls': 0}
