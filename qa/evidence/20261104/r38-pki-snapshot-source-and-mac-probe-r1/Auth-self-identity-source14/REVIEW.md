# Exact self-identity projection SOURCE

The preserved R3 job failed at controller line 75 with process_identity_fixed_python, after its shape/integer gates and after line 784 admitted sys.executable. Line 792 supplied a ProcessReader record. The six rejected compound terms are pid > 1, pgid > 1, uid == 501, birthSec > 0, birthUsec < 1,000,000, and resolved kernel executable == the declared Python launcher. No individual returned value was published in that failed run.

Original ProcessReader 6ca7a8debfe9d9a31d19d1237ca3e84176cc40f5 reads proc_pidinfo at lines 65/74, proc_pidpath at 68, enforces stable numeric identity and birth at 79, and returns Path(actual_path).resolve at 83. This is a different data source from sys.executable. The source proves that distinction, not which actual term failed.

This proposed standalone program reuses the exact original 3302-byte reader and 442-byte Signals. It reads only its current PID twice, preserves all seven-field equality, and publishes the six original booleans individually. It exposes a current kernel path only if it is normalized ASCII <=512 characters strictly under the already-known fixed Python framework directory. Outside that scope it emits null/false, no text or hash. The executable file itself is not opened or qualified.

The new budget is shared 5 seconds, per-read late-return check 4 seconds clipped to the same deadline, outer 60, stdout <=8192. Original C calls cannot be individually preempted; late return cannot pass. Original Path.resolve metadata and interpreter/dyld descriptors are explicitly outside any claim of zero metadata or enumerated interpreter FDs. There is no application FD acquisition, targeted T5 read, file-body read, mkdir, launchd, child, SDK, credentials, provider or product action.

The public diagnostic may exit 0 with an observed false original predicate. That certifies only the fresh observation, not the original R3 value, launchd cause, executable file content, or any guard relaxation. Inconsistent identity, incomplete reads, signal restoration failure/pending signal, late return or incomplete observation fail. No sleep, retry or predecessor replay is included.

The journal is a literal-only derivative of the already reviewed R3 journal: slot, exact request pin and observer prefix. No journal function changes. The new slot is uninitialized. This packet includes 19 pure text/binding checks; it has not compiled or executed Python and has made no Native call. Exact root GO remains necessary.
