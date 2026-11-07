ARGV=["/usr/bin/sandbox-exec","-f","/Users/qianqi/heptabao-public-node-live-denial-20261106-r1-control/consumer.sb","/opt/homebrew/Cellar/node/25.9.0_1/bin/node","--version"]
ENV={"HOME":"/Users/qianqi/heptabao-public-node-live-denial-20261106-r1-empty","TMPDIR":"/Users/qianqi/heptabao-public-node-live-denial-20261106-r1-empty","PATH":"/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin","LANG":"C","LC_ALL":"C"}
import os, select, time
END=time.monotonic()+12.0
PID=os.getpid()
os.write(1,('HEPTA_NODE_GATE_READY '+str(PID)+'\n').encode('ascii'))
ready,_,_=select.select([0],[],[],max(0.0,END-time.monotonic()))
if not ready:os._exit(124)
token=os.read(0,2)
if token!=b'G':os._exit(125)
os.write(1,b'HEPTA_NODE_GATE_RELEASED\n')
os.close(0)
try:
    os.execve('/usr/bin/sandbox-exec',ARGV,ENV)
except BaseException:
    os.write(2,b'HEPTA_NODE_GATE_EXEC_FAILURE\n')
    os._exit(126)
