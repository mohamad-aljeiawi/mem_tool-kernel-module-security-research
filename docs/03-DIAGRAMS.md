# Diagrams

All Mermaid. View in any modern Markdown viewer (VS Code, GitHub, GitLab, Obsidian, etc.).

---

## 1. Toolkit pipeline (high-level)

```mermaid
flowchart TD
    A[user runs<br/>./extract.sh path/to/X.X.sh] --> B[unpack-sh.sh<br/>tail -n +3 + gunzip]
    B --> C[X.X.elf<br/>userland aarch64 PIE]
    C --> D{NDK available?}
    D -->|yes| E[build-dumper.sh<br/>compile dumper.c]
    D -->|no| F[use prebuilt/dumper]
    E --> G[adb push dumper, X.X.elf]
    F --> G
    G --> H[adb reboot<br/>clears bing_rw]
    H --> I[adb wait-for-device]
    I --> J[on-device-runner.sh as root]
    J --> K[install kprobe<br/>on __arm64_sys_init_module]
    K --> L[start dumper in background]
    L --> M[run X.X.elf]
    M --> N{kprobe fires?}
    N -->|yes| O[dumper reads umod buffer<br/>writes /data/local/tmp/dumped_bing_rw.ko]
    N -->|no, /dev/bing_rw existed| P[binary printed<br/>'已刷入驱动']
    O --> Q[adb pull bing_rw.ko]
    P --> Q
    Q --> R[output/X.X.ko<br/>ready for IDA Pro]
```

---

## 2. The `.sh` self-extractor anatomy

```mermaid
flowchart TD
    SH[X.X.sh — typically 30-60 KB]
    SH -->|Line 1| L1["#Telegram @nullnb6"]
    SH -->|Line 2| L2[Single-line shell stub<br/>the loader]
    SH -->|Lines 3..EOF| L3[gzip-compressed binary]

    L2 --> S1["mkdir -p /data/local/tmp/"]
    L2 --> S2["wenjmz=driver:&lt;sha256-base64-32&gt;"]
    L2 --> S3["sed -n LINENO+1,$ p &lt; $0 | gzip -cd<br/>writes binary to /data/local/tmp/$wenjmz"]
    L2 --> S4["chmod 700 $zhixilp"]
    L2 --> S5["(rm -fr $zhixilp) &amp; — anti-forensics"]
    L2 --> S6["$zhixilp ${1+$@} — exec the binary"]
    L2 --> S7["exit $?"]

    S5 -.parallel.-> SUM
    S6 -->|kept open via fd| SUM[binary runs<br/>file already gone from disk]
```

---

## 3. What happens when the binary runs as root

```mermaid
sequenceDiagram
    autonumber
    participant U as Userland binary<br/>(unpacked code)
    participant K as Kernel
    participant FS as VFS / chrdev table
    participant Mod as bing_rw module (in vmalloc)

    Note over U: stage-0: ELF entry, libc init
    U->>U: stage-1: decrypt unpacker
    U->>U: dlopen libhwui, libgui, libvulkan, ...
    U->>U: stage-2: decrypt the embedded .ko bytes
    U->>U: malloc(28728) — get scudo chunk @ tagged ptr
    U->>U: write decrypted bytes into the buffer

    U->>FS: stat("/dev/bing_rw")
    alt /dev/bing_rw exists
        FS-->>U: OK
        U->>U: print "已刷入驱动" and exit (skip init_module)
    else doesn't exist
        FS-->>U: ENOENT
        U->>K: init_module(umod, 28728, "")
        K->>K: copy_from_user(kbuf, umod, 28728)
        K->>K: load_module(): parse ELF, alloc kernel pages,<br/>copy sections, link symbols, run __init
        K->>Mod: bing_rw_init() runs in kernel context
        Mod->>FS: register_chrdev(458, "bing_rw", &fops)
        Mod->>FS: device_create() — /dev/bing_rw appears
        Mod->>K: list_del_init(THIS_MODULE.list) — hide from /proc/modules
        Mod->>K: kobject_del(mkobj.kobj) — hide from /sys/module/
        K-->>U: 0 (success)
        U->>U: printf("刷入成功\n") + exit
    end
```

---

## 4. The kprobe extraction race

```mermaid
sequenceDiagram
    autonumber
    participant Bin as ft_test.elf
    participant K as Kernel
    participant TF as tracefs<br/>(trace_pipe)
    participant D as dumper (C)
    participant Out as /data/local/tmp/<br/>dumped_bing_rw.ko

    D->>K: write kprobe_events:<br/>p:ft_init_x __arm64_sys_init_module umod=+0(%x0):x64 len=+8(%x0):x64
    D->>K: enable kprobes/ft_init_x
    D->>TF: open("/sys/kernel/tracing/trace_pipe")<br/>blocking read

    Note over Bin: starts running
    Bin->>Bin: unpack stages 1, 2; decrypt .ko bytes
    Bin->>K: svc #0 with x8=105 (init_module)
    K->>TF: write event line:<br/>ft_init_x umod=0xb4...3320 len=0x7038
    TF-->>D: read returns line (~µs latency)

    D->>D: parse pid, umod, len from line
    D->>D: umod_addr = umod & 0x00FFFFFFFFFFFFFF<br/>(strip MTE top byte)
    D->>K: open("/proc/<pid>/mem", O_RDONLY)
    D->>K: lseek(umod_addr)
    D->>K: read(buf, 28728)
    K-->>D: 28728 bytes (the .ko bytes)
    D->>Out: write(buf, 28728)

    Note over K: meanwhile init_module is still running<br/>(load_module: parse, link, run __init)

    K-->>Bin: init_module returns 0
    Bin->>Bin: printf("刷入成功") + exit
```

---

## 5. `pt_regs` deref for syscall args on aarch64

```mermaid
flowchart LR
    SVC[binary executes:<br/>mov x0, &lt;umod&gt;<br/>mov x1, &lt;len&gt;<br/>mov x2, &lt;uargs&gt;<br/>mov x8, #105<br/>svc #0]

    SVC -->|enters kernel| WRAP[__arm64_sys_init_module]

    WRAP -->|x0 = pt_regs *| PR[struct pt_regs]
    PR -->|+0x00| R0[regs[0] = umod]
    PR -->|+0x08| R1[regs[1] = len]
    PR -->|+0x10| R2[regs[2] = uargs]
    PR -->|+0x18| R3[regs[3]]
    PR -->|...| RN[...]

    R0 -->|kprobe :x64| TR1[trace_pipe:<br/>umod=0xb4000076ffe73320]
    R1 -->|kprobe :x64| TR2[trace_pipe:<br/>len=0x7038]
```

---

## 6. MTE / TBI top-byte stripping

```mermaid
flowchart LR
    U[umod from kprobe<br/>0xb4 00 00 76 ff e7 33 20] -->|bits 63:56 = MTE tag| T[0xb4]
    U -->|bits 55:0 = real address| A[0x000000076ffe73320]

    style T fill:#fdd
    style A fill:#dfd

    A --> M[mask: addr &amp; 0x00FFFFFFFFFFFFFF]
    M -->|lseek SEEK_SET| MEM[/proc/&lt;pid&gt;/mem]
    MEM --> R[read 28728 bytes<br/>= the .ko file]
```

---

## 7. Module rootkit hide vs. observable surfaces

```mermaid
flowchart LR
    Init[module __init runs] --> H1[list_del_init from modules]
    Init --> H2[kobject_del from sysfs]
    Init --> Reg[register_chrdev<br/>major 458, name bing_rw]
    Init --> Dev[device_create<br/>/dev/bing_rw]

    H1 --> X1[/proc/modules<br/>X HIDDEN/]
    H1 --> X2[lsmod<br/>X HIDDEN/]
    H1 --> X3[rmmod<br/>X ENOENT/]
    H2 --> X4[/sys/module/bing_rw/<br/>X GONE/]

    Reg --> Y1[/proc/devices<br/>✓ shows: 458 bing_rw/]
    Dev --> Y2[ls /dev/bing_rw<br/>✓ exists/]

    Init --> Y3[tracepoint module_load<br/>✓ fires before hide]
    Init --> Y4[BPF/kprobes on init_module<br/>✓ unaffected]

    style X1 fill:#fdd
    style X2 fill:#fdd
    style X3 fill:#fdd
    style X4 fill:#fdd
    style Y1 fill:#dfd
    style Y2 fill:#dfd
    style Y3 fill:#dfd
    style Y4 fill:#dfd
```

---

## 8. Why shell-based extraction lost (latency budgets)

```mermaid
gantt
    title Reaction time vs binary lifetime
    dateFormat X
    axisFormat %s ms
    todayMarker off

    section Binary (ms)
    stage-1 unpack         :a1, 0, 50
    stage-2 + decrypt .ko  :a2, 50, 100
    init_module syscall    :a3, 200, 70
    write success + exit   :a4, 270, 30

    section Shell daemon
    trace_pipe wakeup      :crit, b1, 200, 10
    awk fork + parse       :crit, b2, 210, 30
    dd fork + open + read  :crit, b3, 240, 60
    %% finishes too late: by 300ms binary is gone

    section C dumper
    trace_pipe wakeup      :done, c1, 200, 1
    parse + lseek + read   :done, c2, 201, 1
    write to disk          :done, c3, 202, 1
```

---

## 9. Decision tree: what kind of run gives what

```mermaid
flowchart TD
    Start[run ./X.X.elf]
    Start --> Q1{running as root?}
    Q1 -->|no| Fail1[init_module returns EPERM<br/>binary prints '刷入失败']
    Q1 -->|yes| Q2{ptraced<br/>strace/Frida/gdb?}
    Q2 -->|yes| AntiD[anti-debug burn loop<br/>mremap+mmap+mprotect forever]
    Q2 -->|no| Q3{/dev/bing_rw exists?}
    Q3 -->|yes| Skip[binary prints '已刷入驱动'<br/>exits without init_module]
    Q3 -->|no| Load[binary calls init_module<br/>prints '刷入成功'<br/>kprobe fires - we win!]

    style Fail1 fill:#fdd
    style AntiD fill:#fdd
    style Skip fill:#fdd
    style Load fill:#dfd
```

---

## 10. End-to-end view

```mermaid
flowchart LR
    subgraph Host
        SH[X.X.sh]
        SH -->|tail+gunzip| ELF[X.X.elf]
        DUMC[dumper.c]
        DUMC -->|NDK clang| DUM[dumper aarch64 binary]
    end

    subgraph Device
        ELF -.adb push.-> DT[/data/local/tmp/X.X.elf]
        DUM -.adb push.-> DD[/data/local/tmp/dumper]
        DD -->|root| KP[kprobe installed]
        DT -->|root, no ptracer| RUN[ft_test.elf running]
        KP -.fires.-> EVT[trace_pipe event]
        RUN -.umod ptr.-> EVT
        EVT -.parsed.-> READ[/proc/&lt;pid&gt;/mem read]
        READ --> KO[/data/local/tmp/dumped_bing_rw.ko]
    end

    KO -.adb pull.-> OUT[output/X.X.ko]
    OUT --> IDA[IDA Pro]

    style ELF fill:#cef
    style KO fill:#cfc
    style OUT fill:#cfc
```
