class Signals:
    def __init__(self):
        self.protected=0;self.pending=None
    def receive(self,signum,_frame):
        self.pending=signum
        if not self.protected:raise KeyboardInterrupt()
    def install(self):
        signal.signal(signal.SIGTERM,self.receive);signal.signal(signal.SIGINT,self.receive)
    @contextmanager
    def critical(self):
        self.protected+=1
        try:yield
        finally:self.protected-=1

