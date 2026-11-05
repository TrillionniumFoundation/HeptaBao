import ast
import hashlib
import json

before = fixture["before"]
after = fixture["after"]
old_tree = ast.parse(before, filename="approved-r4.py")
new_tree = ast.parse(after, filename="candidate-r5.py")
compile(new_tree, "candidate-r5.py", "exec")
checks = []
def check(name, value):
    if not value:
        raise AssertionError(name)
    checks.append({"case": name, "passed": True})

def defs(tree):
    return {node.name: node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
old_defs = defs(old_tree)
new_defs = defs(new_tree)
check("all_existing_definitions_except_main_ast_identical",
      all(name in new_defs and ast.dump(node, include_attributes=False) ==
          ast.dump(new_defs[name], include_attributes=False)
          for name, node in old_defs.items() if name != "main"))
check("one_new_pure_selector_only",
      set(new_defs) - set(old_defs) == {"fixed_query_window"})

selected = [node for node in new_tree.body
            if ((isinstance(node, ast.Assign)
                 and any(isinstance(t, ast.Name)
                         and t.id == "DESKTOP_QUERY_WINDOWS"
                         for t in node.targets))
                or (isinstance(node, (ast.ClassDef, ast.FunctionDef))
                    and node.name in ("Refused", "need", "fixed_query_window")))]
namespace = {}
exec(compile(ast.Module(body=selected, type_ignores=[]),
             "selected-fixed-window-components.py", "exec"), namespace)
windows = namespace["DESKTOP_QUERY_WINDOWS"]
select = namespace["fixed_query_window"]
Refused = namespace["Refused"]
check("twelve_canonical_ids",
      list(windows) == [f"{i:02d}" for i in range(1, 13)])
pairs = list(windows.values())
check("exact_unobserved_endpoints",
      pairs[0][0] == 1793865024255 and pairs[-1][1] == 1793871896027)
check("positive_at_most_ten_minute_inclusive_windows",
      all(type(start) is int and type(end) is int and
          0 < end - start + 1 <= 600000 for start, end in pairs))
check("contiguous_nonoverlapping_windows",
      all(pairs[i][1] + 1 == pairs[i + 1][0]
          for i in range(len(pairs) - 1)))
check("exact_inclusive_cardinality_6871773",
      sum(end - start + 1 for start, end in pairs) == 6871773)
check("actual_selector_preserves_all_fixed_intervals",
      all(select(key, 1793871896027) == (start, end, end)
          for key, (start, end) in windows.items()))
check("single_observed_now_clips_end_only",
      all(select(key, start) == (start, start, end)
          and select(key, start + (end-start)//2) ==
              (start, start+(end-start)//2, end)
          and select(key, end+123) == (start, end, end)
          for key, (start, end) in windows.items()))
def refusal(call, code):
    try:
        call()
    except Refused as error:
        return error.code == code
    return False
check("future_interval_refuses_without_scope_widening",
      all(refusal(lambda key=key,start=start: select(key,start-1),
                  "query_window_not_reached")
          for key, (start, _end) in windows.items()))
check("unknown_noncanonical_and_nonstr_window_ids_refuse",
      all(refusal(lambda value=value: select(value,1793871896027),
                  "fixed_window_index")
          for value in ("00","13","1","01 ",1,None,[],{})))
check("noninteger_now_refuses",
      all(refusal(lambda value=value: select("01",value),
                  "query_window_not_reached")
          for value in (True,False,1793871896027.0,"1793871896027",None)))
anchor_start = "        jobs_fd = reader.open_fixed_ancestors()\n"
anchor_end = "        del anchor\n"
def anchor_block(text):
    first = text.index(anchor_start)
    last = text.index(anchor_end, first) + len(anchor_end)
    return text[first:last]
check("anchor_open_read_verify_report_block_byte_exact",
      anchor_block(before) == anchor_block(after))
check("anchor_job_outside_all_windows_still_checked_first",
      1793864424254 < pairs[0][0] and
      after.index(anchor_end) < after.index(
          "        names, count, name_bytes = reader.candidates(") and
      'jobs_fd, query_start, query_end)' in after)
old_configs = next(node for node in old_tree.body
                   if isinstance(node,ast.Assign) and
                   any(isinstance(t,ast.Name) and t.id=="CONFIGS"
                       for t in node.targets))
new_configs = next(node for node in new_tree.body
                   if isinstance(node,ast.Assign) and
                   any(isinstance(t,ast.Name) and t.id=="CONFIGS"
                       for t in node.targets))
check("both_actual_configs_and_original_anchor_floor_unchanged",
      ast.get_source_segment(before,old_configs) ==
      ast.get_source_segment(after,new_configs))
main = new_defs["main"]
time_samples = [node for node in ast.walk(main) if isinstance(node,ast.Call)
                and isinstance(node.func,ast.Attribute)
                and isinstance(node.func.value,ast.Name)
                and node.func.value.id=="time" and node.func.attr=="time_ns"]
check("one_wall_clock_sample_and_fixed_desktop_scope",
      len(time_samples)==1 and
      'need(scope == "desktop-fence", "fixed_desktop_window_scope")' in after)
print(json.dumps({
 "schema":"heptabao.locator-fixed-windows-r5.pure-components.v1",
 "status":"PASS", "checks":checks, "check_count":len(checks),
 "before_sha256":hashlib.sha256(before.encode()).hexdigest(),
 "after_sha256":hashlib.sha256(after.encode()).hexdigest(),
 "range":[pairs[0][0],pairs[-1][1]], "windows":windows,
 "actual_host_access":False, "actual_reader_instances":0,
 "actual_main_calls":0, "actual_fd_operations":0,
 "actual_scandir_operations":0, "actual_child_processes":0,
 "previous_25_components_rerun":False
}, sort_keys=True, indent=2))
