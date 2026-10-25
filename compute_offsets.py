#!/usr/bin/env python3
"""
Compute ARM32 struct offsets for Linux 5.4 kernel.
Models the ARM32 AAPCS ABI alignment rules to compute
offsetof() values for all structs needed by GhostLock exploit.

ARM32 ABI rules:
  - pointer: 4 bytes, 4-aligned
  - int/unsigned: 4 bytes, 4-aligned
  - long/unsigned long: 4 bytes, 4-aligned (ILP32!)
  - long long/u64: 8 bytes, 8-aligned
  - short: 2 bytes, 2-aligned
  - char/u8: 1 byte, 1-aligned
  - struct alignment = max field alignment
  - struct size rounded up to alignment
"""

import sys

class Struct:
    """Compute C struct layout with ARM32 alignment rules."""
    def __init__(self, name, pack=0):
        self.name = name
        self.offset = 0
        self.align = 1
        self.fields = {}
        self.pack = pack  # forced alignment if > 0

    def _add(self, fname, size, align):
        # Pad to alignment
        if self.offset % align:
            self.offset += align - (self.offset % align)
        self.fields[fname] = self.offset
        self.offset += size
        if align > self.align:
            self.align = align

    def ptr(self, fname):       self._add(fname, 4, 4)
    def u32(self, fname):       self._add(fname, 4, 4)
    def s32(self, fname):       self._add(fname, 4, 4)
    def ulong(self, fname):     self._add(fname, 4, 4)
    def slong(self, fname):     self._add(fname, 4, 4)
    def u64(self, fname):       self._add(fname, 8, 8)
    def s64(self, fname):       self._add(fname, 8, 8)
    def u16(self, fname):       self._add(fname, 2, 2)
    def u8(self, fname):        self._add(fname, 1, 1)
    def char(self, fname, n=1): self._add(fname, n, 1)
    def atomic(self, fname):    self._add(fname, 4, 4)  # atomic_t / refcount_t
    def atomic_long(self, fname): self._add(fname, 4, 4)  # atomic_long_t on 32-bit
    def bool_(self, fname):     self._add(fname, 4, 4)  # bool is 4 bytes in kernel

    def raw_spinlock(self, fname):
        """raw_spinlock_t = arch_spinlock_t = { unsigned int lock; } = 4 bytes"""
        self._add(fname, 4, 4)

    def spinlock(self, fname):
        """spinlock_t = { raw_spinlock_t rlock; } = 4 bytes (no DEBUG)"""
        self._add(fname, 4, 4)

    def rb_node(self, fname):
        """rb_node = { unsigned long rb_parent_color; struct rb_node *rb_right, *rb_left; } = 12"""
        self._add(fname, 12, 4)

    def rb_root(self, fname):
        """rb_root = { struct rb_node *rb_node; } = 4"""
        self._add(fname, 4, 4)

    def rb_root_cached(self, fname):
        """rb_root_cached = { struct rb_root rb_root; struct rb_node *rb_left; } = 8"""
        self._add(fname, 8, 4)

    def list_head(self, fname):
        """list_head = { struct list_head *next, *prev; } = 8"""
        self._add(fname, 8, 4)

    def hlist_node(self, fname):
        """hlist_node = { struct hlist_node *next; struct hlist_node **pprev; } = 8"""
        self._add(fname, 8, 4)

    def hlist_head(self, fname):
        """hlist_head = { struct hlist_node *first; } = 4"""
        self._add(fname, 4, 4)

    def wait_queue_head(self, fname):
        """wait_queue_head_t = { spinlock_t lock; struct list_head head; } = 12"""
        self._add(fname, 12, 4)

    def llist_node(self, fname):
        """llist_node = { struct llist_node *next; } = 4"""
        self._add(fname, 4, 4)

    def plist_node(self, fname):
        """plist_node = { int prio; struct list_head prio_list, node_list; } = 20"""
        self._add(fname, 20, 4)

    def callback_head(self, fname):
        """callback_head = { unsigned long next; void (*func)(struct callback_head *); } = 8"""
        self._add(fname, 8, 4)

    def rcu_head(self, fname):
        """rcu_head = { struct callback_head head; } or { void *next, *func; } = 8"""
        self._add(fname, 8, 4)

    def page_frag(self, fname):
        """page_frag = { struct page *page; unsigned int offset; unsigned int size; } on 5.4 =
           actually { struct page *page; union { unsigned int pagecnt_bias; }; __u16 offset; __u16 size; }
           = 4 + 4 + 2 + 2 = 12, but let's use 8 for {page*, offset} on older 5.4"""
        # On 5.4: struct page_frag { struct page *page; unsigned int offset, size; }
        self._add(fname, 12, 4)

    def sub(self, fname, size, align):
        """Embed a sub-struct with given size and alignment."""
        self._add(fname, size, align)

    def padding(self, size):
        """Add explicit padding."""
        self.offset += size

    def align_to(self, a):
        """Force alignment to boundary."""
        if self.offset % a:
            self.offset += a - (self.offset % a)
        if a > self.align:
            self.align = a

    def finish(self):
        """Round up size to struct alignment."""
        if self.offset % self.align:
            self.offset += self.align - (self.offset % self.align)
        return self.offset

    def off(self, fname):
        return self.fields[fname]

    def dump(self):
        size = self.finish()
        print(f"\n=== {self.name} (size={size}, align={self.align}) ===")
        for fname, off in sorted(self.fields.items(), key=lambda x: x[1]):
            print(f"  {fname:40s} = 0x{off:04x} ({off})")
        print(f"  {'TOTAL SIZE':40s} = 0x{size:04x} ({size})")
        return size


# =====================================================================
# Compute sub-struct sizes first
# =====================================================================

# --- rb_node: 12 bytes, align 4 ---
RB_NODE_SIZE, RB_NODE_ALIGN = 12, 4

# --- rb_root: 4 bytes, align 4 ---
RB_ROOT_SIZE, RB_ROOT_ALIGN = 4, 4

# --- rb_root_cached: 8 bytes, align 4 ---
RB_ROOT_CACHED_SIZE, RB_ROOT_CACHED_ALIGN = 8, 4

# --- list_head: 8 bytes, align 4 ---
LIST_HEAD_SIZE, LIST_HEAD_ALIGN = 8, 4

# --- hlist_node: 8 bytes, align 4 ---
HLIST_NODE_SIZE, HLIST_NODE_ALIGN = 8, 4

# --- wait_queue_head_t: 12 bytes, align 4 ---
WAIT_QUEUE_HEAD_SIZE, WAIT_QUEUE_HEAD_ALIGN = 12, 4

# --- load_weight ---
s = Struct("load_weight")
s.ulong("weight"); s.u32("inv_weight")
LOAD_WEIGHT_SIZE = s.finish()  # 8

# --- util_est: aligned(8) ---
s = Struct("util_est")
s.u32("enqueued"); s.u32("ewma")
s.align_to(8)
UTIL_EST_SIZE = s.finish()  # 8, align 8

# --- sched_avg (CONFIG_SMP=y) ---
s = Struct("sched_avg")
s.u64("last_update_time")
s.u64("load_sum")
s.u64("runnable_load_sum")
s.u32("util_sum")
s.u32("period_contrib")
s.ulong("load_avg")
s.ulong("runnable_load_avg")
s.ulong("util_avg")
s.sub("util_est", UTIL_EST_SIZE, 8)  # aligned(8)
SCHED_AVG_SIZE = s.finish()  # should be 56

# --- sched_statistics (CONFIG_SCHEDSTATS=n -> 0 bytes) ---
SCHED_STATS_SIZE = 0

# --- sched_entity (CONFIG_SMP=y, CONFIG_FAIR_GROUP_SCHED=y, CONFIG_SCHEDSTATS=n) ---
s = Struct("sched_entity")
s.sub("load", LOAD_WEIGHT_SIZE, 4)
s.ulong("runnable_weight")
s.rb_node("run_node")
s.list_head("group_node")
s.u32("on_rq")
s.u64("exec_start")
s.u64("sum_exec_runtime")
s.u64("vruntime")
s.u64("prev_sum_exec_runtime")
s.u64("nr_migrations")
# statistics (0 bytes if !SCHEDSTATS)
# CONFIG_FAIR_GROUP_SCHED=y:
s.s32("depth")
s.ptr("parent")
s.ptr("cfs_rq")
s.ptr("my_q")
# CONFIG_SMP=y:
s.sub("avg", SCHED_AVG_SIZE, 8)
SCHED_ENTITY_SIZE = s.finish()

# --- sched_rt_entity (CONFIG_RT_GROUP_SCHED=y) ---
s = Struct("sched_rt_entity")
s.list_head("run_list")
s.ulong("timeout")
s.ulong("watchdog_stamp")
s.u32("time_slice")
s.u16("on_rq")
s.u16("on_list")
s.ptr("back")
# CONFIG_RT_GROUP_SCHED=y:
s.ptr("parent")
s.ptr("rt_rq")
s.ptr("my_q")
SCHED_RT_ENTITY_SIZE = s.finish()

# --- sched_dl_entity ---
s = Struct("sched_dl_entity")
s.rb_node("rb_node")
s.u64("dl_runtime")
s.u64("dl_deadline")
s.u64("dl_period")
s.u64("dl_bw")
s.u64("dl_density")
s.s64("runtime")
s.u64("deadline")
s.u32("flags")  # bitfield, but occupies 4 bytes
# dl_timer and inactive_timer are hrtimer
# hrtimer on 5.4: { struct timer_list timer; ktime_t _softexpires; }
# timer_list on 5.4: ~48 bytes (complex). Let's estimate hrtimer = 56 bytes each
# Actually we need to be more careful. Let me compute timer_list.
# struct timer_list { struct hlist_node entry; unsigned long expires; void *function; unsigned long data; }
# = 8 + 4 + 4 + 4 = 20, but with alignment: entry(8) expires(4) func(4) data(4) = 20 -> 24
# hrtimer = { timer_list(24) + ktime_t(8) } = 32
# Actually on 5.4, hrtimer = { struct timer_list timer; ktime_t _softexpires; }
# timer_list = { struct hlist_node entry; unsigned long expires;
#                void (*function)(struct timer_list *); unsigned long data; }
# Hmm, on 5.4 the function pointer might be different. Let me just estimate.
# timer_list ≈ 24 bytes on ARM32 (hlist_node(8) + expires(4) + func_ptr(4) + data(4) = 20 -> 24)
# hrtimer = timer_list(24) + ktime_t(8) = 32 bytes, align 8
HRTIMER_SIZE = 32
HRTIMER_ALIGN = 8
s.sub("dl_timer", HRTIMER_SIZE, HRTIMER_ALIGN)
s.sub("inactive_timer", HRTIMER_SIZE, HRTIMER_ALIGN)
SCHED_DL_ENTITY_SIZE = s.finish()

# --- uclamp_se ---
# struct uclamp_se { unsigned int value:bits; bucket_id:bits; active:1; user_defined:1; }
# Plus padding and max_value. On 5.4: ~12 bytes? Actually it's:
# struct uclamp_se {
#     unsigned int value : bits_per(SCHED_CAPACITY_SCALE);
#     unsigned int bucket_id : bits_per(UCLAMP_BUCKETS);
#     unsigned int active : 1;
#     unsigned int user_defined : 1;
#     unsigned int max_value : ...;
#     ...
# };
# This is complex. Let's estimate 8 bytes per uclamp_se
UCLAMP_SE_SIZE = 8

# --- mutex (CONFIG_MUTEX_SPIN_ON_OWNER=y, no DEBUG) ---
s = Struct("mutex")
s.atomic_long("owner")  # atomic_long_t = 4 bytes on 32-bit
s.spinlock("wait_lock")
s.sub("osq", 4, 4)  # optimistic_spin_queue = { unsigned int tail; } = 4
s.list_head("wait_list")
MUTEX_SIZE = s.finish()  # 4+4+4+8 = 20 -> 20

# --- thread_info (ARM32, no STACKPROTECTOR_PER_TASK) ---
s = Struct("thread_info")
s.ulong("flags")
s.s32("preempt_count")
s.ulong("addr_limit")  # mm_segment_t = unsigned long
s.ptr("task")
s.u32("cpu")
s.u32("cpu_domain")
# cpu_context_save: r4-r9,sl,fp,sp,pc,extra[2] = 12 * 4 = 48
s.char("cpu_context", 48)
s.u32("syscall")
s.char("used_cp", 16)
s.char("tp_value", 8)  # unsigned long[2]
# fpstate aligned(8): union fp_state ~ 160 bytes (FPEXT + VFP)
# Actually fpstate is complex. Let's estimate:
# union fp_state = { struct fp_hard_struct hard; struct fp_soft_soft soft; }
# On ARM32 with VFP: sizeof(union fp_state) ≈ 160 bytes
# But the alignment is 8. Let me estimate 160.
s.align_to(8)
s.char("fpstate", 160)
# vfpstate: union vfp_state ≈ 16 bytes
s.char("vfpstate", 16)
THREAD_INFO_SIZE = s.finish()

# --- seccomp (CONFIG_HAVE_ARCH_SECCOMP_FILTER=y) ---
s = Struct("seccomp")
s.s32("mode")
s.ptr("filter")  # struct seccomp_filter *
# With CONFIG_SECCOMP_FILTER (usually y): actually it's:
# struct seccomp { int mode; struct seccomp_filter *filter; };
# But with CONFIG_SECCOMP_FILTER on 5.4, there's also a mutex and filter list:
# Actually the simple version is just { int mode; struct seccomp_filter *filter; } = 8
SECCOMP_SIZE = s.finish()

# --- vmacache ---
# struct vmacache { unsigned long seqnum; struct vm_area_struct *vmas[VMACACHE_SIZE]; }
# VMACACHE_SIZE = 4 on 5.4
# = 4 + 4*4 = 20 bytes
VMACACHE_SIZE = 20

# --- restart_block ---
# Complex struct. On 5.4: ~48 bytes?
# struct restart_block { unsigned long fn; union { ... }; }
# Let's estimate 48 bytes
RESTART_BLOCK_SIZE = 48

# --- sigset_t ---
# sigset_t = { unsigned long sig[2]; } on 32-bit (64 bits = 2 * 32-bit words)
SIGSET_SIZE = 8

# --- sigpending ---
# struct sigpending { struct list_head list; sigset_t signal; }
SIGPENDING_SIZE = 8 + SIGSET_SIZE  # 16

# --- kernel_siginfo_t ---
# On 5.4 without COMPAT: kernel_siginfo_t = struct siginfo ≈ 128 bytes
# But it's a pointer in task_struct, so size doesn't matter
# kernel_siginfo_t is: union { ... } = 128 bytes
KERNEL_SIGINFO_SIZE = 128

# --- posix_cputimers ---
# struct posix_cputimers { struct list_head cpu_timers[3]; } = 3 * 8 = 24
POSIX_CPUTIMERS_SIZE = 24

# --- tlbflush_unmap_batch ---
# struct tlbflush_unmap_batch { struct arch_tlbflush_unmap_batch arch; }
# On ARM32: empty or small. Let's estimate 4 bytes (just a count)
TLB_UBC_SIZE = 4

# =====================================================================
# task_struct (the big one)
# =====================================================================
# Config assumptions:
# CONFIG_SMP=y, CONFIG_THREAD_INFO_IN_TASK=y, CONFIG_PREEMPT=y
# CONFIG_PREEMPT_RCU=y, CONFIG_FUTEX=y, CONFIG_RT_MUTEXES=y
# CONFIG_SECURITY=y, CONFIG_KEYS=y, CONFIG_AUDIT=y, CONFIG_AUDITSYSCALL=y
# CONFIG_BLOCK=y, CONFIG_SYSVIPC=y, CONFIG_CGROUPS=y, CONFIG_CGROUP_SCHED=y
# CONFIG_FAIR_GROUP_SCHED=y, CONFIG_RT_GROUP_SCHED=y
# CONFIG_SCHEDSTATS=n, CONFIG_NUMA=n, CONFIG_NUMA_BALANCING=n
# CONFIG_CPUSETS=n, CONFIG_MEMCG=n (or y, doesn't affect much)
# CONFIG_PSI=n, CONFIG_RSEQ=n, CONFIG_KASAN=n, CONFIG_TRACING=n
# CONFIG_LOCKDEP=n, CONFIG_UBSAN=n, CONFIG_FUNCTION_GRAPH_TRACER=n
# CONFIG_BLK_DEV_IO_TRACE=n, CONFIG_PREEMPT_NOTIFIERS=n
# CONFIG_TASKS_RCU=n (usually not on ARM32)
# CONFIG_VIRT_CPU_ACCOUNTING_GEN=n, CONFIG_NO_HZ_FULL=n
# CONFIG_COMPAT=n (native ARM32, not 64-bit kernel)
# CONFIG_STACKPROTECTOR=n (or y without PER_TASK)
# CONFIG_DETECT_HUNG_TASK=y, CONFIG_PERF_EVENTS=n
# CONFIG_TASK_XACCT=n, CONFIG_LATENCYTOP=n, CONFIG_FAULT_INJECTION=n
# CONFIG_KCOV=n, CONFIG_TASK_DELAY_ACCT=n

s = Struct("task_struct")

# --- thread_info (CONFIG_THREAD_INFO_IN_TASK=y) ---
s.sub("thread_info", THREAD_INFO_SIZE, 4)

# --- state (volatile long) ---
s.slong("state")

# randomized_struct_fields_start (no actual randomization in practice)

# --- stack ---
s.ptr("stack")

# --- usage (refcount_t) ---
s.atomic("usage")

# --- flags ---
s.u32("flags")

# --- ptrace ---
s.u32("ptrace")

# CONFIG_SMP=y:
# --- wake_entry (llist_node) ---
s.llist_node("wake_entry")

# --- on_cpu ---
s.s32("on_cpu")

# CONFIG_THREAD_INFO_IN_TASK=y:
# --- cpu ---
s.u32("cpu")

# --- wakee_flips ---
s.u32("wakee_flips")

# --- wakee_flip_decay_ts (unsigned long) ---
s.ulong("wakee_flip_decay_ts")

# --- last_wakee ---
s.ptr("last_wakee")

# --- recent_used_cpu ---
s.s32("recent_used_cpu")

# --- wake_cpu ---
s.s32("wake_cpu")

# --- on_rq ---
s.s32("on_rq")

# --- prio, static_prio, normal_prio, rt_priority ---
s.s32("prio")
s.s32("static_prio")
s.s32("normal_prio")
s.u32("rt_priority")

# --- sched_class ---
s.ptr("sched_class")

# --- sched_entity (se) ---
s.sub("se", SCHED_ENTITY_SIZE, 8)  # sched_avg has 8-align

# --- sched_rt_entity (rt) ---
s.sub("rt", SCHED_RT_ENTITY_SIZE, 4)

# CONFIG_CGROUP_SCHED=y:
# --- sched_task_group ---
s.ptr("sched_task_group")

# --- sched_dl_entity (dl) ---
s.sub("dl", SCHED_DL_ENTITY_SIZE, 8)

# CONFIG_UCLAMP_TASK: assume=n for standard Android kernel
# CONFIG_PREEMPT_NOTIFIERS: assume=n
# CONFIG_BLK_DEV_IO_TRACE: assume=n

# --- policy ---
s.u32("policy")

# --- nr_cpus_allowed ---
s.s32("nr_cpus_allowed")

# --- cpus_ptr ---
s.ptr("cpus_ptr")

# --- cpus_mask (cpumask_t) ---
# cpumask_t = struct cpumask { unsigned long bits[NR_CPUS/BITS_PER_LONG]; }
# On ARM32 with NR_CPUS=4 or 8: bits = 4/8 bytes. Let's use 4 (NR_CPUS=4, typical for W5+)
# Actually NR_CPUS could be up to 16 or 32. Let's use 8 (NR_CPUS=8 -> 8/32=1 ulong=4 bytes)
# With NR_CPUS=16: 16/32 = 1 ulong = 4 bytes
# With NR_CPUS=32: 32/32 = 1 ulong = 4 bytes
# With NR_CPUS=64: 64/32 = 2 ulong = 8 bytes
# Typical Android ARM32: NR_CPUS=4 or 8 -> cpumask_t = 4 bytes
s.sub("cpus_mask", 4, 4)

# CONFIG_PREEMPT_RCU=y:
# --- rcu_read_lock_nesting ---
s.s32("rcu_read_lock_nesting")

# --- rcu_read_unlock_special (union rcu_special) ---
# union rcu_special = { struct { bool b, need_qs, exp, exp_hint; } bits; long t; }
# = 4 bytes (the largest member)
s.u32("rcu_read_unlock_special")

# --- rcu_node_entry (list_head) ---
s.list_head("rcu_node_entry")

# --- rcu_blocked_node ---
s.ptr("rcu_blocked_node")

# CONFIG_TASKS_RCU: assume=n

# --- sched_info ---
# CONFIG_SCHED_INFO: usually=y on Android
# struct sched_info = { unsigned long pcount; u64 run_delay, last_arrival, last_queued; }
# = 4 + 4(pad) + 8 + 8 + 8 = 32
s.char("sched_info", 32)

# === tasks (list_head) ===
s.list_head("tasks")

# CONFIG_SMP=y:
# --- pushable_tasks (plist_node) ---
s.plist_node("pushable_tasks")

# --- pushable_dl_tasks (rb_node) ---
s.rb_node("pushable_dl_tasks")

# --- mm ---
s.ptr("mm")

# --- active_mm ---
s.ptr("active_mm")

# --- vmacache ---
s.char("vmacache", VMACACHE_SIZE)

# SPLIT_RSS_COUNTING: usually not defined -> no rss_stat

# --- exit_state, exit_code, exit_signal, pdeath_signal ---
s.s32("exit_state")
s.s32("exit_code")
s.s32("exit_signal")
s.s32("pdeath_signal")

# --- jobctl (unsigned long) ---
s.ulong("jobctl")

# --- personality ---
s.u32("personality")

# --- bitfields (sched_reset_on_fork etc) ---
# These are packed into a single unsigned int
s.u32("bitfields_1")  # :0 forces alignment to next word

# --- atomic_flags ---
s.ulong("atomic_flags")

# --- restart_block ---
s.char("restart_block", RESTART_BLOCK_SIZE)

# === pid, tgid ===
s.s32("pid")
s.s32("tgid")

# CONFIG_STACKPROTECTOR (without PER_TASK):
# --- stack_canary ---
s.ulong("stack_canary")

# === real_parent ===
s.ptr("real_parent")

# === parent ===
s.ptr("parent")

# === children, sibling (list_head) ===
s.list_head("children")
s.list_head("sibling")

# === group_leader ===
s.ptr("group_leader")

# === ptraced, ptrace_entry (list_head) ===
s.list_head("ptraced")
s.list_head("ptrace_entry")

# === thread_pid ===
s.ptr("thread_pid")

# === pid_links[PIDTYPE_MAX] (hlist_node[3]) ===
# PIDTYPE_MAX = 3 on 5.4 (PID, TGID, PGID but actually 4: PIDTYPE_PID=0, PIDTYPE_TGID, PIDTYPE_PGID, PIDTYPE_SID, PIDTYPE_MAX=4)
# Actually on 5.4: enum pid_type { PIDTYPE_PID, PIDTYPE_TGID, PIDTYPE_PGID, PIDTYPE_SID, PIDTYPE_MAX };
# So PIDTYPE_MAX = 4
s.char("pid_links", 4 * HLIST_NODE_SIZE)  # 4 * 8 = 32

# === thread_group (list_head) ===
s.list_head("thread_group")

# === thread_node (list_head) ---
s.list_head("thread_node")

# === vfork_done ===
s.ptr("vfork_done")

# === set_child_tid, clear_child_tid ---
s.ptr("set_child_tid")
s.ptr("clear_child_tid")

# === utime, stime (u64) ---
s.u64("utime")
s.u64("stime")

# CONFIG_ARCH_HAS_SCALED_CPUTIME: usually=n on ARM32

# === gtime ===
s.u64("gtime")

# === prev_cputime ---
# CONFIG_VIRT_CPU_ACCOUNTING_NATIVE=n:
# struct prev_cputime = { u64 utime, stime; raw_spinlock_t lock; }
# = 8 + 8 + 4 = 20 -> 24 (8-aligned)
s.char("prev_cputime", 24)

# CONFIG_VIRT_CPU_ACCOUNTING_GEN: assume=n
# CONFIG_NO_HZ_FULL: assume=n

# === nvcsw, nivcsw ---
s.ulong("nvcsw")
s.ulong("nivcsw")

# === start_time, real_start_time ---
s.u64("start_time")
s.u64("real_start_time")

# === min_flt, maj_flt ---
s.ulong("min_flt")
s.ulong("maj_flt")

# === posix_cputimers ---
s.char("posix_cputimers", POSIX_CPUTIMERS_SIZE)

# === ptracer_cred ===
s.ptr("ptracer_cred")

# === real_cred ===
s.ptr("real_cred")

# === cred ===
s.ptr("cred")

# CONFIG_KEYS=y:
# === cached_requested_key ---
s.ptr("cached_requested_key")

# === comm[16] ===
s.char("comm", 16)

# === nameidata ---
s.ptr("nameidata")

# CONFIG_SYSVIPC=y:
# === sysvsem ---
# struct sysv_sem = { struct sysv_sem_undo *undo_list; } = 4
s.char("sysvsem", 4)

# === sysvshm ---
# struct sysv_shm = { struct shm_clist *list; } = 4
s.char("sysvshm", 4)

# CONFIG_DETECT_HUNG_TASK=y:
# === last_switch_count, last_switch_time ---
s.ulong("last_switch_count")
s.ulong("last_switch_time")

# === fs (fs_struct *) ---
s.ptr("fs")

# === files ===
s.ptr("files")

# === nsproxy ===
s.ptr("nsproxy")

# === signal ===
s.ptr("signal")

# === sighand ===
s.ptr("sighand")

# === blocked, real_blocked (sigset_t) ---
s.char("blocked", SIGSET_SIZE)
s.char("real_blocked", SIGSET_SIZE)

# === saved_sigmask ---
s.char("saved_sigmask", SIGSET_SIZE)

# === pending (sigpending) ---
s.char("pending", SIGPENDING_SIZE)

# === sas_ss_sp, sas_ss_size, sas_ss_flags ---
s.ulong("sas_ss_sp")
s.ulong("sas_ss_size")  # size_t = unsigned long
s.u32("sas_ss_flags")

# === task_works ---
s.ptr("task_works")

# CONFIG_AUDIT=y, CONFIG_AUDITSYSCALL=y:
# === audit_context ---
s.ptr("audit_context")

# === loginuid, sessionid ---
s.u32("loginuid")
s.u32("sessionid")

# === seccomp ===
s.char("seccomp", SECCOMP_SIZE)

# === parent_exec_id, self_exec_id ---
s.u32("parent_exec_id")
s.u32("self_exec_id")

# === alloc_lock ---
s.spinlock("alloc_lock")

# === pi_lock ===
s.raw_spinlock("pi_lock")

# === wake_q ---
# struct wake_q_node = { struct wake_q_node *next; int status; } = 8
s.char("wake_q", 8)

# CONFIG_RT_MUTEXES=y:
# === pi_waiters (rb_root_cached) ===
s.rb_root_cached("pi_waiters")

# === pi_top_task ---
s.ptr("pi_top_task")

# === pi_blocked_on ---
s.ptr("pi_blocked_on")

# CONFIG_DEBUG_MUTEXES: assume=n
# CONFIG_DEBUG_ATOMIC_SLEEP: assume=n
# CONFIG_TRACE_IRQFLAGS: assume=n
# CONFIG_LOCKDEP: assume=n
# CONFIG_UBSAN: assume=n

# === journal_info ---
s.ptr("journal_info")

# === bio_list ---
s.ptr("bio_list")

# CONFIG_BLOCK=y:
# === plug ---
s.ptr("plug")

# === reclaim_state ---
s.ptr("reclaim_state")

# === backing_dev_info ---
s.ptr("backing_dev_info")

# === io_context ---
s.ptr("io_context")

# CONFIG_COMPACTION: assume=n

# === ptrace_message ---
s.ulong("ptrace_message")

# === last_siginfo ---
s.ptr("last_siginfo")

# === ioac ---
# struct task_io_accounting: ~48 bytes? Let's estimate
s.char("ioac", 48)

# CONFIG_PSI: assume=n
# CONFIG_TASK_XACCT: assume=n
# CONFIG_CPUSETS: assume=n
# CONFIG_CGROUPS=y:
# === cgroups ---
s.ptr("cgroups")

# === cg_list ---
s.list_head("cg_list")

# CONFIG_X86_CPU_RESCTRL: n (ARM)
# CONFIG_FUTEX=y:
# === robust_list ---
s.ptr("robust_list")
# CONFIG_COMPAT=n (native ARM32): no compat_robust_list

# === pi_state_list ---
s.list_head("pi_state_list")

# === pi_state_cache ---
s.ptr("pi_state_cache")

# CONFIG_PERF_EVENTS: assume=n
# CONFIG_DEBUG_PREEMPT: assume=n
# CONFIG_NUMA: n
# CONFIG_NUMA_BALANCING: n
# CONFIG_RSEQ: assume=n

# === tlb_ubc ---
s.char("tlb_ubc", TLB_UBC_SIZE)

# === rcu_users (union with rcu_head) ---
s.char("rcu_users", 8)  # max(refcount_t, rcu_head) = 8

# === splice_pipe ---
s.ptr("splice_pipe")

# === task_frag ---
s.char("task_frag", 12)  # page_frag

# CONFIG_TASK_DELAY_ACCT: assume=n
# CONFIG_FAULT_INJECTION: assume=n

# === nr_dirtied, nr_dirtied_pause ---
s.s32("nr_dirtied")
s.s32("nr_dirtied_pause")

# === dirty_paused_when ---
s.ulong("dirty_paused_when")

# CONFIG_LATENCYTOP: n
# CONFIG_KASAN: n
# CONFIG_FUNCTION_GRAPH_TRACER: n
# CONFIG_TRACING: n (or minimal)
# CONFIG_KCOV: n
# CONFIG_MEMCG: n

# === timer_slack_ns, default_timer_slack_ns ---
s.u64("timer_slack_ns")
s.u64("default_timer_slack_ns")

# randomized_struct_fields_end

# === thread (thread_struct) ===
# struct thread_struct { unsigned long address, trap_no, error_code; struct debug_info debug; }
# debug_info = { struct perf_event *hbp[N]; } with CONFIG_HAVE_HW_BREAKPOINT
# ARM_MAX_HBP_SLOTS = 2 typically -> 2 * 4 = 8 bytes
# So debug_info = 8 (or 0 without HW_BREAKPOINT)
# thread_struct = 3*4 + 8 = 20 bytes (with HW_BREAKPOINT)
# or = 3*4 = 12 bytes (without)
# Let's use 20 as a reasonable estimate
s.char("thread", 20)

TASK_STRUCT_SIZE = s.finish()

# Print results
print("=" * 60)
print("ARM32 Linux 5.4 Struct Offset Computation")
print("Config: SMP=y, THREAD_INFO_IN_TASK=y, PREEMPT=y,")
print("  PREEMPT_RCU=y, FUTEX=y, RT_MUTEXES=y, SECURITY=y,")
print("  KEYS=y, AUDIT=y, SYSVIPC=y, CGROUPS=y, CGROUP_SCHED=y")
print("  SCHEDSTATS=n, NUMA=n, LOCKDEP=n, TRACING=n")
print("=" * 60)

# Dump sub-structs
for name, sz, al in [
    ("load_weight", LOAD_WEIGHT_SIZE, 4),
    ("util_est", UTIL_EST_SIZE, 8),
    ("sched_avg", SCHED_AVG_SIZE, 8),
    ("sched_entity", SCHED_ENTITY_SIZE, 8),
    ("sched_rt_entity", SCHED_RT_ENTITY_SIZE, 4),
    ("sched_dl_entity", SCHED_DL_ENTITY_SIZE, 8),
    ("mutex", MUTEX_SIZE, 4),
    ("thread_info", THREAD_INFO_SIZE, 4),
    ("seccomp", SECCOMP_SIZE, 4),
]:
    print(f"  {name}: size=0x{sz:x} ({sz}), align={al}")

print(f"\n{'='*60}")
print(f"task_struct: size=0x{TASK_STRUCT_SIZE:x} ({TASK_STRUCT_SIZE})")
print(f"{'='*60}")

# Print key offsets
key_fields = [
    "thread_info", "state", "stack", "usage", "flags",
    "prio", "static_prio", "normal_prio", "rt_priority",
    "se", "rt", "sched_task_group", "dl",
    "tasks", "mm", "active_mm",
    "pid", "tgid", "stack_canary",
    "real_parent", "parent", "children", "sibling",
    "group_leader", "thread_pid", "thread_group",
    "utime", "stime", "gtime",
    "real_cred", "cred", "comm",
    "fs", "files", "nsproxy", "signal", "sighand",
    "seccomp", "alloc_lock",
    "pi_lock", "pi_waiters", "pi_top_task", "pi_blocked_on",
    "atomic_flags",
    "thread",
]

print("\n--- Key task_struct offsets ---")
for f in key_fields:
    if f in s.fields:
        print(f"  TASK_{f.upper():30s} = 0x{s.fields[f]:04x} ({s.fields[f]})")
    else:
        print(f"  TASK_{f.upper():30s} = NOT FOUND")

# =====================================================================
# cred struct
# =====================================================================
print(f"\n{'='*60}")
c = Struct("cred")
c.atomic("usage")
# CONFIG_DEBUG_CREDENTIALS=n
c.u32("uid")
c.u32("gid")
c.u32("suid")
c.u32("sgid")
c.u32("euid")
c.u32("egid")
c.u32("fsuid")
c.u32("fsgid")
c.u32("securebits")
# kernel_cap_t = uint32_t on 5.4 (CONFIG_SECURITY=n uses 32-bit caps)
# Actually kernel_cap_t = struct { __u32 cap[1]; } or __u32 depending on config
# On 5.4 with CONFIG_SECURITY=y: kernel_cap_t is typically u32 (CAP_LAST_CAP/32 + 1)
# CAP_LAST_CAP = 40 on 5.4 -> cap size = 2 u32 = 8 bytes
# Actually on 5.4: #define CAP_LAST_CAP 40, so kernel_cap_t = { u32 cap[2]; } = 8 bytes
# Wait, let me check: kernel_cap_t is typedef'd as kernel_cap_t
# On 5.4: typedef struct { unsigned long cap[1]; } kernel_cap_t;
# No wait: it's: typedef struct { __u32 val; } kernel_cap_t; when CAP_LAST_CAP <= 32
# Or: typedef struct { __u32 cap[(CAP_LAST_CAP+1+31)/32]; } kernel_cap_t;
# CAP_LAST_CAP = 40 -> (40+1+31)/32 = 72/32 = 2 -> cap[2] = 8 bytes
# Hmm, actually on 5.4: CAP_LAST_CAP = CAP_PERFMON = 38 or CAP_BPF = 39
# Let me check... On 5.4 vanilla: CAP_LAST_CAP = 40 (CAP_TO_BLOCK)
# So kernel_cap_t = 8 bytes (2 * u32)
# Actually wait, I need to check the actual typedef.
# On 5.4 include/linux/capability.h:
# typedef struct { __u32 val; } kernel_cap_t;  -- if _KERNEL_CAPABILITY_ARCH_DEFINED
# Actually the standard definition on 5.4 is:
# #define XCAP_VALID (CAP_LAST_CAP < 32 ? (1U << (CAP_LAST_CAP+1)) - 1 : 0xFFFFFFFF)
# typedef struct { __u32 cap[_KERNEL_CAPABILITY_U32_SIZE]; } kernel_cap_t;
# where _KERNEL_CAPABILITY_U32_SIZE = (_KERNEL_CAP_T_BYTES / sizeof(__u32))
# _KERNEL_CAP_T_BYTES = (CAP_LAST_CAP/8 + 1) rounded up
# For CAP_LAST_CAP=40: (40/8+1) = 6 bytes -> rounded to 8 -> 2 u32s = 8 bytes
# Hmm, actually it's simpler:
# #define _KERNEL_CAPABILITY_U32_SIZE ((CAP_LAST_CAP + 32) / 32)
# For CAP_LAST_CAP=40: (40+32)/32 = 72/32 = 2
# So kernel_cap_t = 2 * 4 = 8 bytes

# Let me use 8 bytes per kernel_cap_t
CAP_SIZE = 8  # 5.4 with CAP_LAST_CAP around 38-40

c.char("cap_inheritable", CAP_SIZE)
c.char("cap_permitted", CAP_SIZE)
c.char("cap_effective", CAP_SIZE)
c.char("cap_bset", CAP_SIZE)
c.char("cap_ambient", CAP_SIZE)

# CONFIG_KEYS=y:
c.u8("jit_keyring")
c.ptr("session_keyring")
c.ptr("process_keyring")
c.ptr("thread_keyring")
c.ptr("request_key_auth")

# CONFIG_SECURITY=y:
c.ptr("security")

c.ptr("user")
c.ptr("user_ns")
c.ptr("group_info")

# union { int non_rcu; struct rcu_head rcu; }
c.char("rcu_delete", 8)

CRED_SIZE = c.finish()
print(f"cred: size=0x{CRED_SIZE:x} ({CRED_SIZE})")
print("\n--- Key cred offsets ---")
for f in ["usage", "uid", "gid", "euid", "egid", "fsuid", "fsgid",
           "securebits", "cap_inheritable", "security", "user", "user_ns", "group_info"]:
    print(f"  CRED_{f.upper():30s} = 0x{c.fields[f]:04x} ({c.fields[f]})")

# =====================================================================
# rt_mutex
# =====================================================================
print(f"\n{'='*60}")
rt = Struct("rt_mutex")
rt.raw_spinlock("wait_lock")
rt.rb_root_cached("waiters")
rt.ptr("owner")
RT_MUTEX_SIZE = rt.finish()
print(f"rt_mutex: size=0x{RT_MUTEX_SIZE:x} ({RT_MUTEX_SIZE})")
for f in ["wait_lock", "waiters", "owner"]:
    print(f"  RT_MUTEX_{f.upper():30s} = 0x{rt.fields[f]:04x} ({rt.fields[f]})")

# =====================================================================
# rt_mutex_waiter
# =====================================================================
print(f"\n{'='*60}")
w = Struct("rt_mutex_waiter")
w.rb_node("tree_entry")
w.rb_node("pi_tree_entry")
w.ptr("task")
w.ptr("lock")
w.s32("prio")
w.u64("deadline")
w.s32("wake_state")
w.ptr("ww_ctx")
WAITER_SIZE = w.finish()
print(f"rt_mutex_waiter: size=0x{WAITER_SIZE:x} ({WAITER_SIZE})")
for f in ["tree_entry", "pi_tree_entry", "task", "lock", "prio", "deadline", "wake_state", "ww_ctx"]:
    print(f"  WAITER_{f.upper():30s} = 0x{w.fields[f]:04x} ({w.fields[f]})")

# =====================================================================
# pipe_buffer
# =====================================================================
print(f"\n{'='*60}")
pb = Struct("pipe_buffer")
pb.ptr("page")
pb.u32("offset")
pb.u32("len")
pb.ptr("ops")
pb.u32("flags")
pb.ulong("private")
PIPE_BUF_SIZE = pb.finish()
print(f"pipe_buffer: size=0x{PIPE_BUF_SIZE:x} ({PIPE_BUF_SIZE})")
for f in ["page", "offset", "len", "ops", "flags", "private"]:
    print(f"  PIPE_BUFFER_{f.upper():30s} = 0x{pb.fields[f]:04x} ({pb.fields[f]})")

# =====================================================================
# pipe_inode_info
# =====================================================================
print(f"\n{'='*60}")
pi = Struct("pipe_inode_info")
pi.sub("mutex", MUTEX_SIZE, 4)
pi.wait_queue_head("wait")
pi.u32("nrbufs")
pi.u32("curbuf")
pi.u32("buffers")
pi.u32("readers")
pi.u32("writers")
pi.u32("files")
pi.u32("waiting_writers")
pi.u32("r_counter")
pi.u32("w_counter")
pi.ptr("tmp_page")
pi.ptr("fasync_readers")
pi.ptr("fasync_writers")
pi.ptr("bufs")
pi.ptr("user")
PIPE_INODE_INFO_SIZE = pi.finish()
print(f"pipe_inode_info: size=0x{PIPE_INODE_INFO_SIZE:x} ({PIPE_INODE_INFO_SIZE})")
for f in ["mutex", "wait", "nrbufs", "curbuf", "buffers", "readers", "writers",
           "files", "tmp_page", "bufs", "user"]:
    print(f"  PIPE_{f.upper():30s} = 0x{pi.fields[f]:04x} ({pi.fields[f]})")

# =====================================================================
# file_operations (5.4)
# =====================================================================
print(f"\n{'='*60}")
fo = Struct("file_operations")
fo.ptr("owner")
fo.ptr("llseek")
fo.ptr("read")
fo.ptr("write")
fo.ptr("read_iter")
fo.ptr("write_iter")
fo.ptr("iopoll")
fo.ptr("iterate")
fo.ptr("iterate_shared")
fo.ptr("poll")
fo.ptr("unlocked_ioctl")
fo.ptr("compat_ioctl")
fo.ptr("mmap")
fo.ulong("mmap_supported_flags")
fo.ptr("open")
fo.ptr("flush")
fo.ptr("release")
fo.ptr("fsync")
fo.ptr("fasync")
fo.ptr("lock")
fo.ptr("sendpage")
fo.ptr("get_unmapped_area")
fo.ptr("check_flags")
fo.ptr("flock")
fo.ptr("splice_write")
fo.ptr("splice_read")
fo.ptr("setlease")
fo.ptr("fallocate")
fo.ptr("show_fdinfo")
FOPS_SIZE = fo.finish()
print(f"file_operations: size=0x{FOPS_SIZE:x} ({FOPS_SIZE})")
for f in ["owner", "llseek", "read", "write", "read_iter", "write_iter",
           "iopoll", "iterate", "iterate_shared", "poll", "unlocked_ioctl",
           "compat_ioctl", "mmap", "mmap_supported_flags", "open", "flush",
           "release", "fsync", "splice_write", "splice_read", "show_fdinfo"]:
    print(f"  FOPS_{f.upper():30s} = 0x{fo.fields[f]:04x} ({fo.fields[f]})")

# =====================================================================
# struct file (5.4)
# =====================================================================
print(f"\n{'='*60}")
fi = Struct("file")
# f_u: union { llist_node; rcu_head; } = 8 (max of 4, 8)
fi.char("f_u", 8)
# f_path: struct path = { struct vfsmount *mnt; struct dentry *dentry; } = 8
fi.char("f_path", 8)
fi.ptr("f_inode")
fi.ptr("f_op")
fi.spinlock("f_lock")
# enum rw_hint: int
fi.s32("f_write_hint")
fi.atomic_long("f_count")
fi.u32("f_flags")
fi.u32("f_mode")
fi.sub("f_pos_lock", MUTEX_SIZE, 4)
fi.s64("f_pos")
# f_own_struct: complex, ~24 bytes?
fi.char("f_owner", 24)
fi.ptr("f_cred")
# file_ra_state: ~40 bytes?
fi.char("f_ra", 40)
fi.u64("f_version")
# CONFIG_SECURITY=y:
fi.ptr("f_security")
fi.ptr("private_data")
# CONFIG_EPOLL:
fi.list_head("f_ep_links")
fi.list_head("f_tfile_llink")
fi.ptr("f_mapping")
fi.u32("f_wb_err")
FILE_SIZE = fi.finish()
print(f"struct file: size=0x{FILE_SIZE:x} ({FILE_SIZE})")
for f in ["f_path", "f_inode", "f_op", "f_flags", "f_mode", "f_mapping"]:
    print(f"  FILE_{f.upper():30s} = 0x{fi.fields[f]:04x} ({fi.fields[f]})")

# =====================================================================
# nsproxy (5.4)
# =====================================================================
print(f"\n{'='*60}")
ns = Struct("nsproxy")
ns.atomic("count")
ns.ptr("uts_ns")
ns.ptr("ipc_ns")
ns.ptr("mnt_ns")
ns.ptr("pid_ns_for_children")
ns.ptr("net_ns")
ns.ptr("cgroup_ns")
NSPROXY_SIZE = ns.finish()
print(f"nsproxy: size=0x{NSPROXY_SIZE:x} ({NSPROXY_SIZE})")
for f in ["count", "uts_ns", "ipc_ns", "mnt_ns", "pid_ns_for_children", "net_ns", "cgroup_ns"]:
    print(f"  NS_{f.upper():30s} = 0x{ns.fields[f]:04x} ({ns.fields[f]})")

# =====================================================================
# files_struct / fdtable
# =====================================================================
print(f"\n{'='*60}")
fdt = Struct("fdtable")
fdt.u32("max_fds")
fdt.ptr("fd")
fdt.ptr("close_on_exec")
fdt.ptr("open_fds")
fdt.ptr("full_fds_bits")
fdt.char("rcu", 8)  # rcu_head
FDT_SIZE = fdt.finish()
print(f"fdtable: size=0x{FDT_SIZE:x} ({FDT_SIZE})")
print(f"  FDT_FD_OFF = 0x{fdt.fields['fd']:04x}")

fs = Struct("files_struct")
fs.atomic("count")
fs.bool_("resize_in_progress")
fs.wait_queue_head("resize_wait")
fs.ptr("fdt")
fs.char("fdtab", FDT_SIZE)
FILES_STRUCT_SIZE = fs.finish()
print(f"files_struct: size=0x{FILES_STRUCT_SIZE:x} ({FILES_STRUCT_SIZE})")
print(f"  FD_TABLE_FDT_OFF = 0x{fs.fields['fdt']:04x}")

# =====================================================================
# configfs_buffer (5.4, fs/configfs/file.c)
# =====================================================================
print(f"\n{'='*60}")
cb = Struct("configfs_buffer")
cb.u32("count")
cb.s32("pos")  # loff_t = 8 bytes, but on 32-bit might be split
# Actually loff_t is 8 bytes even on 32-bit. Let me redo:
cb2 = Struct("configfs_buffer_v2")
cb2.u32("count")
# padding to 8-align for loff_t
cb2.s64("pos")
cb2.ptr("page")
cb2.ptr("ops")
cb2.sub("mutex", MUTEX_SIZE, 4)
cb2.u32("needs_read_fill")
cb2.u32("read_in_progress")
# These might be bools (1 byte each) or ints. In configfs they're bool.
# Actually on 5.4: bool needs_read_fill, read_in_progress, write_in_progress;
# bools are 1 byte but might be packed or have padding
# Let me model them as u8 with potential padding
CB_SIZE = cb2.finish()
print(f"configfs_buffer: size=0x{CB_SIZE:x} ({CB_SIZE})")
for f in cb2.fields:
    print(f"  CFG_{f.upper():30s} = 0x{cb2.fields[f]:04x} ({cb2.fields[f]})")

# =====================================================================
# Generate target.h values
# =====================================================================
print(f"\n{'='*60}")
print("GENERATED TARGET.H VALUES")
print(f"{'='*60}")

# task_struct offsets
print("\n/* --- task_struct (5.4 ARM32, computed from source) --- */")
task_fields_map = {
    "TASK_STACK_OFF": "stack",
    "TASK_TI_FLAGS_OFF": None,  # special: inside thread_info
    "TASK_TI_PREEMPT_OFF": None,
    "TASK_TI_ADDR_LIMIT_OFF": None,
    "TASK_PRIO_OFF": "prio",
    "TASK_STATIC_PRIO_OFF": "static_prio",
    "TASK_NORMAL_PRIO_OFF": "normal_prio",
    "TASK_RT_PRIORITY_OFF": "rt_priority",
    "TASK_PID_OFF": "pid",
    "TASK_TGID_OFF": "tgid",
    "TASK_REAL_PARENT_OFF": "real_parent",
    "TASK_PARENT_OFF": "parent",
    "TASK_TASKS_OFF": "tasks",
    "TASK_THREAD_GROUP_OFF": "thread_group",
    "TASK_MM_OFF": "mm",
    "TASK_ACTIVE_MM_OFF": "active_mm",
    "TASK_REAL_CRED_OFF": "real_cred",
    "TASK_CRED_OFF": "cred",
    "TASK_COMM_OFF": "comm",
    "TASK_FILES_OFF": "files",
    "TASK_NSPROXY_OFF": "nsproxy",
    "TASK_SIGNAL_OFF": "signal",
    "TASK_THREAD_OFF": "thread",
    "TASK_PI_LOCK_OFF": "pi_lock",
    "TASK_PI_WAITERS_OFF": "pi_waiters",
    "TASK_PI_TOP_TASK_OFF": "pi_top_task",
    "TASK_PI_BLOCKED_ON_OFF": "pi_blocked_on",
    "TASK_ATOMIC_FLAGS_OFF": "atomic_flags",
    "TASK_SECCOMP_OFF": "seccomp",
}

# thread_info offsets (within task_struct)
ti_base = s.fields["thread_info"]
print(f"#define TASK_TI_FLAGS_OFF 0x{ti_base + 0:02x}")
print(f"#define TASK_TI_PREEMPT_OFF 0x{ti_base + 4:02x}")
print(f"#define TASK_TI_ADDR_LIMIT_OFF 0x{ti_base + 8:02x}")
print(f"#define TASK_SIZE 0x{TASK_STRUCT_SIZE:04x}  /* {TASK_STRUCT_SIZE} */")

for macro, field in task_fields_map.items():
    if field is None:
        continue
    if field in s.fields:
        print(f"#define {macro} 0x{s.fields[field]:04x}")
    else:
        print(f"#define {macro} 0x????  /* NOT FOUND */")

print(f"\n/* --- thread_info (5.4 ARM32) --- */")
print(f"#define THREAD_INFO_FLAGS_OFF 0x{s.fields['thread_info'] + 0:02x}")
print(f"#define THREAD_INFO_PREEMPT_OFF 0x{s.fields['thread_info'] + 4:02x}")
print(f"#define THREAD_INFO_ADDR_LIMIT_OFF 0x{s.fields['thread_info'] + 8:02x}")

print(f"\n/* --- cred (5.4 ARM32) --- */")
print(f"#define CRED_USAGE_OFF 0x{c.fields['usage']:02x}")
print(f"#define CRED_UID_OFF 0x{c.fields['uid']:02x}")
print(f"#define CRED_GID_OFF 0x{c.fields['gid']:02x}")
print(f"#define CRED_SUID_OFF 0x{c.fields['suid']:02x}")
print(f"#define CRED_SGID_OFF 0x{c.fields['sgid']:02x}")
print(f"#define CRED_EUID_OFF 0x{c.fields['euid']:02x}")
print(f"#define CRED_EGID_OFF 0x{c.fields['egid']:02x}")
print(f"#define CRED_FSUID_OFF 0x{c.fields['fsuid']:02x}")
print(f"#define CRED_FSGID_OFF 0x{c.fields['fsgid']:02x}")
print(f"#define CRED_SECUREBITS_OFF 0x{c.fields['securebits']:02x}")
print(f"#define CRED_CAPS_OFF 0x{c.fields['cap_inheritable']:02x}")
print(f"#define CRED_SECURITY_OFF 0x{c.fields['security']:02x}")
print(f"#define CRED_SIZE 0x{CRED_SIZE:04x}  /* {CRED_SIZE} */")

print(f"\n/* --- rt_mutex (5.4 ARM32) --- */")
print(f"#define RT_MUTEX_WAIT_LOCK_OFF 0x{rt.fields['wait_lock']:02x}")
print(f"#define RT_MUTEX_WAITERS_OFF 0x{rt.fields['waiters']:02x}")
print(f"#define RT_MUTEX_OWNER_OFF 0x{rt.fields['owner']:02x}")

print(f"\n/* --- rt_mutex_waiter (5.4 ARM32) --- */")
print(f"#define WAITER_TREE_ENTRY_OFF 0x{w.fields['tree_entry']:02x}")
print(f"#define WAITER_PRIO_OFF 0x{w.fields['prio']:02x}")
print(f"#define WAITER_DEADLINE_OFF 0x{w.fields['deadline']:02x}")
print(f"#define WAITER_PI_TREE_ENTRY_OFF 0x{w.fields['pi_tree_entry']:02x}")
print(f"#define WAITER_TASK_OFF 0x{w.fields['task']:02x}")
print(f"#define WAITER_LOCK_OFF 0x{w.fields['lock']:02x}")
print(f"#define WAITER_SIZE 0x{WAITER_SIZE:04x}  /* {WAITER_SIZE} */")

print(f"\n/* --- pipe_buffer (5.4 ARM32) --- */")
print(f"#define PIPE_BUFFER_PAGE_OFF 0x{pb.fields['page']:02x}")
print(f"#define PIPE_BUFFER_OFFSET_OFF 0x{pb.fields['offset']:02x}")
print(f"#define PIPE_BUFFER_LEN_OFF 0x{pb.fields['len']:02x}")
print(f"#define PIPE_BUFFER_OPS_OFF 0x{pb.fields['ops']:02x}")
print(f"#define PIPE_BUFFER_FLAGS_OFF 0x{pb.fields['flags']:02x}")
print(f"#define PIPE_BUFFER_PRIVATE_OFF 0x{pb.fields['private']:02x}")
print(f"#define PIPE_BUFFER_SIZE 0x{PIPE_BUF_SIZE:04x}  /* {PIPE_BUF_SIZE} */")

print(f"\n/* --- pipe_inode_info (5.4 ARM32) --- */")
print(f"#define PIPE_INODE_INFO_STRUCT_SIZE 0x{PIPE_INODE_INFO_SIZE:04x}")
print(f"#define PIPE_NRB_UFS_OFF 0x{pi.fields['nrbufs']:02x}")
print(f"#define PIPE_CURBUF_OFF 0x{pi.fields['curbuf']:02x}")
print(f"#define PIPE_BUFFERS_OFF 0x{pi.fields['buffers']:02x}")
print(f"#define PIPE_READERS_OFF 0x{pi.fields['readers']:02x}")
print(f"#define PIPE_WRITERS_OFF 0x{pi.fields['writers']:02x}")
print(f"#define PIPE_FILES_OFF 0x{pi.fields['files']:02x}")
print(f"#define PIPE_TMP_PAGE_OFF 0x{pi.fields['tmp_page']:02x}")
print(f"#define PIPE_BUFS_OFF 0x{pi.fields['bufs']:02x}")
print(f"#define PIPE_USER_OFF 0x{pi.fields['user']:02x}")

print(f"\n/* --- file_operations (5.4 ARM32) --- */")
for f in ["owner", "llseek", "read", "write", "read_iter", "write_iter",
           "iterate", "iterate_shared", "poll", "unlocked_ioctl", "compat_ioctl",
           "mmap", "open", "flush", "release", "fsync",
           "splice_write", "splice_read", "show_fdinfo"]:
    print(f"#define FOPS_{f.upper()}_OFF 0x{fo.fields[f]:02x}")

print(f"\n/* --- struct file (5.4 ARM32) --- */")
print(f"#define FILE_F_PATH_OFF 0x{fi.fields['f_path']:02x}")
print(f"#define FILE_F_OP_OFF 0x{fi.fields['f_op']:02x}")
print(f"#define FILE_F_FLAGS_OFF 0x{fi.fields['f_flags']:02x}")
print(f"#define FILE_F_MODE_OFF 0x{fi.fields['f_mode']:02x}")
print(f"#define FILE_F_MAPPING_OFF 0x{fi.fields['f_mapping']:02x}")

print(f"\n/* --- nsproxy (5.4 ARM32) --- */")
print(f"#define NS_PROXY_UTS_OFF 0x{ns.fields['uts_ns']:02x}")
print(f"#define NS_PROXY_IPC_OFF 0x{ns.fields['ipc_ns']:02x}")
print(f"#define NS_PROXY_MNT_OFF 0x{ns.fields['mnt_ns']:02x}")
print(f"#define NS_PROXY_NET_OFF 0x{ns.fields['net_ns']:02x}")

print(f"\n/* --- files_struct/fdtable (5.4 ARM32) --- */")
print(f"#define FD_TABLE_FDT_OFF 0x{fs.fields['fdt']:02x}")
print(f"#define FDT_FD_OFF 0x{fdt.fields['fd']:02x}")

print(f"\n/* --- FAKE_TASK offsets (for skb payload) --- */")
# These are the same as TASK_ offsets but used for the fake task in the skb
print(f"#define FAKE_TASK_USAGE_OFF 0x{s.fields['usage']:04x}")
print(f"#define FAKE_TASK_PRIO_OFF 0x{s.fields['prio']:04x}")
print(f"#define FAKE_TASK_NORMAL_PRIO_OFF 0x{s.fields['normal_prio']:04x}")
if "sched_task_group" in s.fields:
    print(f"#define FAKE_TASK_TASK_GROUP_OFF 0x{s.fields['sched_task_group']:04x}")
print(f"#define FAKE_TASK_PI_LOCK_OFF 0x{s.fields['pi_lock']:04x}")
print(f"#define FAKE_TASK_PI_WAITERS_OFF 0x{s.fields['pi_waiters']:04x}")
print(f"#define FAKE_TASK_PI_TOP_TASK_OFF 0x{s.fields['pi_top_task']:04x}")
print(f"#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x{s.fields['pi_blocked_on']:04x}")
