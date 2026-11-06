def structure_fields(raw,target):
    need(isinstance(raw,bytes) and len(raw)<=262144,'bounded_launchctl_print')
    lines=raw.decode('utf-8','strict').splitlines()
    need(1<=len(lines)<=4096 and lines[0].strip()==target+' = {','exact_launchctl_target')
    fields={};arguments=[];depth=1;in_arguments=False;arguments_seen=False
    allowed=('path','program','pid','state','runs','last exit code','last terminating signal')
    for line in lines[1:]:
        text=line.strip()
        if in_arguments:
            if text=='}':
                in_arguments=False;depth-=1;continue
            need(depth==2 and text and '{' not in text and '}' not in text
                 and len(text)<=16384,'plain_fixed_launchctl_argument')
            arguments.append(text)
            need(len(arguments)<=32,'bounded_launchctl_arguments')
            continue
        if depth==1 and text=='arguments = {':
            need(not arguments_seen,'one_launchctl_arguments_block')
            arguments_seen=True;in_arguments=True;depth+=1;continue
        if depth==1 and ' = ' in text and not text.endswith('{'):
            name,value=text.split(' = ',1)
            if name in allowed:
                need(name not in fields,'unique_launchctl_field');fields[name]=value
        depth+=text.count('{')-text.count('}')
        need(depth>=0,'balanced_launchctl_print')
        if depth==0:
            need(text=='}' and line==lines[-1],'one_complete_launchctl_record')
    need(depth==0 and not in_arguments and arguments_seen,'complete_launchctl_arguments')
    fields['arguments']=arguments
    return fields

