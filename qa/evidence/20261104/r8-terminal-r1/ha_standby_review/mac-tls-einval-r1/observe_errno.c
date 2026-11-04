/* Diagnostic only: one existing Rust test process. Never inspect I/O buffers.
 * Each replacement calls its original exactly once, preserves return and errno,
 * and records only failed EINVAL syscalls plus finite call-count metadata.
 * dyld excludes the interposing image when resolving calls to the original.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <stdint.h>

enum { OPT, GETOPT, READ, WRITE, READV, WRITEV, RECV, SEND, RECVFROM,
       SENDTO, CONNECT, BIND, LISTEN, ACCEPT, SHUTDOWN, POLL, COUNT };
static _Atomic unsigned long calls[COUNT];
static _Atomic unsigned long errors;
static const char *names[COUNT] = {"setsockopt", "getsockopt", "read", "write",
    "readv", "writev", "recv", "send", "recvfrom", "sendto", "connect", "bind",
    "listen", "accept", "shutdown", "poll"};

static int loopback_port(int fd, int peer) {
    struct sockaddr_storage a;
    socklen_t n = sizeof(a);
    memset(&a, 0, sizeof(a));
    int rc = peer ? getpeername(fd, (struct sockaddr *)&a, &n)
                  : getsockname(fd, (struct sockaddr *)&a, &n);
    if (rc != 0) return -1;
    if (a.ss_family == AF_INET) {
        const struct sockaddr_in *v = (const struct sockaddr_in *)&a;
        if ((ntohl(v->sin_addr.s_addr) >> 24) == 127) return ntohs(v->sin_port);
    }
    if (a.ss_family == AF_INET6) {
        const struct sockaddr_in6 *v = (const struct sockaddr_in6 *)&a;
        if (IN6_IS_ADDR_LOOPBACK(&v->sin6_addr)) return ntohs(v->sin6_port);
    }
    return -2; /* No non-loopback address is disclosed. */
}

static void error_record(int which, int fd, long long rc, int saved,
                         unsigned long long requested, int level, int option,
                         unsigned int optlen, long long sec, long long usec) {
    if (rc >= 0 || saved != EINVAL) return;
    unsigned long sequence = atomic_fetch_add_explicit(&errors, 1, memory_order_relaxed) + 1;
    if (sequence <= 32) {
        int local = loopback_port(fd, 0), peer = loopback_port(fd, 1);
        char line[512];
        int n = snprintf(line, sizeof(line),
            "HB_EINVAL_EVENT {\"sequence\":%lu,\"call\":\"%s\",\"fd\":%d,\"result\":%lld,\"errno\":%d,\"requested\":%llu,\"level\":%d,\"option\":%d,\"optlen\":%u,\"timeval_sec\":%lld,\"timeval_usec\":%lld,\"local_loopback_port\":%d,\"peer_loopback_port\":%d}\n",
            sequence, names[which], fd, rc, saved, requested, level, option, optlen,
            sec, usec, local, peer);
        if (n > 0 && (size_t)n < sizeof(line)) (void)write(STDERR_FILENO, line, (size_t)n);
    }
}

#define BEGIN(k) atomic_fetch_add_explicit(&calls[k], 1, memory_order_relaxed)
#define END(k,fd,rc,requested) do { int saved_errno = errno; \
    error_record(k,fd,(long long)(rc),saved_errno,(unsigned long long)(requested),-1,-1,0,0,0); \
    errno = saved_errno; return rc; } while (0)
#define INTERPOSE(replacement,original) \
    __attribute__((used)) static const struct { const void *new_fn; const void *old_fn; } \
    pair_##original __attribute__((section("__DATA,__interpose"))) = { \
      (const void *)(uintptr_t)&replacement, (const void *)(uintptr_t)&original }

static int observed_setsockopt(int fd, int level, int option, const void *value, socklen_t len) {
    BEGIN(OPT);
    int rc = setsockopt(fd, level, option, value, len), saved_errno = errno;
    long long sec = 0, usec = 0;
    if (rc < 0 && saved_errno == EINVAL && value && level == SOL_SOCKET &&
        (option == SO_RCVTIMEO || option == SO_SNDTIMEO) && len == sizeof(struct timeval)) {
        struct timeval tv; memcpy(&tv, value, sizeof(tv));
        sec = (long long)tv.tv_sec; usec = (long long)tv.tv_usec;
    }
    error_record(OPT, fd, rc, saved_errno, 0, level, option, len, sec, usec);
    errno = saved_errno; return rc;
}
INTERPOSE(observed_setsockopt, setsockopt);
static int observed_getsockopt(int fd,int level,int option,void *v,socklen_t *n) { BEGIN(GETOPT); int r=getsockopt(fd,level,option,v,n); END(GETOPT,fd,r,0); }
INTERPOSE(observed_getsockopt, getsockopt);
static ssize_t observed_read(int fd,void *v,size_t n) { BEGIN(READ); ssize_t r=read(fd,v,n); END(READ,fd,r,n); }
INTERPOSE(observed_read, read);
static ssize_t observed_write(int fd,const void *v,size_t n) { BEGIN(WRITE); ssize_t r=write(fd,v,n); END(WRITE,fd,r,n); }
INTERPOSE(observed_write, write);
static ssize_t observed_readv(int fd,const struct iovec *v,int n) { BEGIN(READV); ssize_t r=readv(fd,v,n); END(READV,fd,r,n); }
INTERPOSE(observed_readv, readv);
static ssize_t observed_writev(int fd,const struct iovec *v,int n) { BEGIN(WRITEV); ssize_t r=writev(fd,v,n); END(WRITEV,fd,r,n); }
INTERPOSE(observed_writev, writev);
static ssize_t observed_recv(int fd,void *v,size_t n,int flags) { BEGIN(RECV); ssize_t r=recv(fd,v,n,flags); END(RECV,fd,r,n); }
INTERPOSE(observed_recv, recv);
static ssize_t observed_send(int fd,const void *v,size_t n,int flags) { BEGIN(SEND); ssize_t r=send(fd,v,n,flags); END(SEND,fd,r,n); }
INTERPOSE(observed_send, send);
static ssize_t observed_recvfrom(int fd,void *v,size_t n,int flags,struct sockaddr *a,socklen_t *l) { BEGIN(RECVFROM); ssize_t r=recvfrom(fd,v,n,flags,a,l); END(RECVFROM,fd,r,n); }
INTERPOSE(observed_recvfrom, recvfrom);
static ssize_t observed_sendto(int fd,const void *v,size_t n,int flags,const struct sockaddr *a,socklen_t l) { BEGIN(SENDTO); ssize_t r=sendto(fd,v,n,flags,a,l); END(SENDTO,fd,r,n); }
INTERPOSE(observed_sendto, sendto);
static int observed_connect(int fd,const struct sockaddr *a,socklen_t n) { BEGIN(CONNECT); int r=connect(fd,a,n); END(CONNECT,fd,r,n); }
INTERPOSE(observed_connect, connect);
static int observed_bind(int fd,const struct sockaddr *a,socklen_t n) { BEGIN(BIND); int r=bind(fd,a,n); END(BIND,fd,r,n); }
INTERPOSE(observed_bind, bind);
static int observed_listen(int fd,int n) { BEGIN(LISTEN); int r=listen(fd,n); END(LISTEN,fd,r,n); }
INTERPOSE(observed_listen, listen);
static int observed_accept(int fd,struct sockaddr *a,socklen_t *n) { BEGIN(ACCEPT); int r=accept(fd,a,n); END(ACCEPT,fd,r,0); }
INTERPOSE(observed_accept, accept);
static int observed_shutdown(int fd,int how) { BEGIN(SHUTDOWN); int r=shutdown(fd,how); END(SHUTDOWN,fd,r,how); }
INTERPOSE(observed_shutdown, shutdown);
static int observed_poll(struct pollfd *p,nfds_t n,int timeout) { BEGIN(POLL); int r=poll(p,n,timeout); END(POLL,-1,r,n); }
INTERPOSE(observed_poll, poll);

__attribute__((constructor)) static void loaded(void) {
    int saved_errno = errno;
    const char msg[] = "HB_EINVAL_OBSERVER_LOADED v1\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg)-1);
    errno = saved_errno;
}
__attribute__((destructor)) static void finished(void) {
    int saved_errno = errno;
    for (int i=0;i<COUNT;i++) {
        char line[192];
        int n=snprintf(line,sizeof(line),"HB_EINVAL_COUNT {\"call\":\"%s\",\"count\":%lu}\n",
            names[i],atomic_load_explicit(&calls[i],memory_order_relaxed));
        if(n>0 && (size_t)n<sizeof(line)) (void)write(STDERR_FILENO,line,(size_t)n);
    }
    char line[128];
    int n=snprintf(line,sizeof(line),"HB_EINVAL_TOTAL %lu\n",atomic_load_explicit(&errors,memory_order_relaxed));
    if(n>0 && (size_t)n<sizeof(line)) (void)write(STDERR_FILENO,line,(size_t)n);
    errno=saved_errno;
}
