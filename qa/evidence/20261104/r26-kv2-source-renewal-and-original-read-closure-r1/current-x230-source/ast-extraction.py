import ast,json
from pathlib import Path
d=json.loads(Path(__file__).with_name("r26_x230_ast_input.json").read_text())
out={}
for name,row in d["files"].items():
    parsed={}
    for side,text in row.items():
        tree=ast.parse(text)
        funcs={n.name:ast.get_source_segment(text,n) for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
        const={}
        for n in tree.body:
            if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
                try:const[n.targets[0].id]=ast.literal_eval(n.value)
                except (ValueError,TypeError):pass
        parsed[side]={"funcs":funcs,"constants":const}
    a,b=parsed["before"],parsed["after"]
    equal=sorted(k for k in a["funcs"] if k in b["funcs"] and a["funcs"][k]==b["funcs"][k])
    changed=[{"name":k,"before":a["funcs"][k],"after":b["funcs"][k]} for k in a["funcs"] if k in b["funcs"] and a["funcs"][k]!=b["funcs"][k]]
    added={k:v for k,v in b["funcs"].items() if k not in a["funcs"]}
    removed={k:v for k,v in a["funcs"].items() if k not in b["funcs"]}
    out[name]={"before_count":len(a["funcs"]),"after_count":len(b["funcs"]),"equal":equal,"changed":changed,"added":added,"removed":removed,"before_constants":a["constants"],"after_constants":b["constants"]}
print(json.dumps({"schema":"heptabao.root.x230.ast-extraction.r1","module_execution":False,"remote_calls":0,"files":out},sort_keys=True))
