import ast,contextlib,json,types
phase="def close_observer_once(observer):\n    key=id(observer)\n    if key in observer_close_results:return observer_close_results[key]\n    with critical():\n        observer_close_results[key]=False\n        try:\n            observer.close();observer_close_results[key]=True\n        except BaseException:pass\n    return observer_close_results[key]\n"
close="    def close(self):\n        if not self.child_ends_closed:\n            for fd in self.child_fds:\n                try:\n                    os.close(fd)\n                except OSError:\n                    pass\n        for name in ('request_read', 'response_write'):\n            fd = getattr(self, name, None)\n            if fd is not None:\n                try:\n                    os.close(fd)\n                except OSError:\n                    pass\n                setattr(self, name, None)\n"
observed=[]
def fail_close(fd):
 observed.append(fd)
 raise OSError('synthetic close failure')
method=ast.parse('class O:\n'+close).body[0]
ns={'os':types.SimpleNamespace(close=fail_close)}
exec(compile(ast.Module(body=[method],type_ignores=[]),'<exact-observer-close>','exec'),ns)
obj=ns['O']();obj.child_ends_closed=True;obj.request_read=11;obj.response_write=12
space={'critical':contextlib.nullcontext,'observer_close_results':{}}
exec(compile(ast.parse(phase),'<exact-phase-close-wrapper>','exec'),space)
result=space['close_observer_once'](obj)
print(json.dumps({'schema':'heptabao.mac-observer-close-mock-counterexample.v1','source_blobs':{'phase':'2d8a431a145858a09c95884c4f0d2fc4cc58157b','observer':'bf63fb2beb4d5e7ed04dcdddb1c18323f56a694e'},'actual_functions_selected':True,'fake_close_errors':len(observed),'fake_descriptors_attempted':observed,'wrapper_reported_close_success':result,'fields_cleared':[obj.request_read,obj.response_write],'real_descriptors_touched':0,'child_processes':0,'network_requests':0,'host_access':False},sort_keys=True))
assert result is True and observed==[11,12]
