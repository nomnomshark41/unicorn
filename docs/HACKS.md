# Dirty Hacks in Unicorn

Unicorn is built on top of QEMU and exposes a simple CPU emulation API. To achieve
this, Unicorn makes several modifications to the QEMU internals that go beyond normal
feature additions. This document catalogues the significant "dirty hacks" — workarounds
that rely on undocumented behaviour or abuse data structures in ways they were not
designed for.

---

## 1. Reusing `MemoryRegion::container` to Store the Snapshot Level

**File:** `qemu/softmmu/memory.c:278`, `uc.c:3016–3021`

When a memory region is moved out of the address space (e.g. during a snapshot
rollback), Unicorn needs to remember which snapshot level the region belonged to so
it can be restored correctly later. The `MemoryRegion` struct does not have a field
for this, so Unicorn (ab)uses the `container` pointer — which is normally `NULL` for
a detached region — to store the integer snapshot level via a pointer cast:

```c
/* dirty hack to save the snapshot level */
mr->container = (void *)(intptr_t)uc->snapshot_level;
```

When restoring a snapshot, the value is read back with the reverse cast and
`container` is set to `NULL` before the region is reinserted:

```c
// same dirty hack as in memory_moveout see qemu/softmmu/memory.c
level = (intptr_t)mr->container;
mr->container = NULL;
```

---

## 2. Overriding the Program Counter Inside `tb_find`

**File:** `qemu/accel/tcg/translate-all.c:1166`

QEMU's `tb_find` function determines the current PC by calling
`cpu_get_tb_cpu_state`, which reads the PC from the CPU register state. Unicorn
needs to look up (or generate) a translation block for an *explicit* target address
that may differ from the architectural PC at that moment, so it simply overwrites the
local variable immediately after the call:

```c
cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

// Unicorn: Our hack here.
pc = addr;
```

---

## 3. ARM BE32 (Big-Endian 32-bit) Support Hacks

**Files:** `qemu/target/arm/cpu.h:3101`, `qemu/target/arm/cpu.h:3238`,
`qemu/target/arm/cpu.c:2182`

QEMU's system emulation requires ARM instruction fetches to always be
little-endian. Unicorn supports BE32 mode (big-endian code *and* data, as used by
pre-ARMv7 big-endian user-mode programs) by making two targeted changes:

1. **`arm_sctlr_b`** — a feature check that would block BE32 on ARMv7+ is
   commented out so the `SCTLR_B` bit is always honoured:

   ```c
   // Unicorn: Our hack to support BE32 mode
   // !arm_feature(env, ARM_FEATURE_V7) &&
   (env->cp15.sctlr_el[1] & SCTLR_B) != 0;
   ```

2. **`bswap_code`** — instead of always returning `0` (little-endian code fetch),
   Unicorn returns `sctlr_b` so that code is byte-swapped when BE32 is active:

   ```c
   // return 0;
   // Unicorn: Our hack to support BE32 for system emulation, which
   //          I believe shouldn't have existed...
   return sctlr_b;
   ```

---

## 4. Disabling an `is_limm` Assertion on AArch64 Hosts

**File:** `qemu/tcg/aarch64/tcg-target.inc.c:835`

When generating AArch64 host code for logical-immediate instructions, QEMU asserts
that the value is a valid AArch64 logical immediate (`is_limm`). On Apple Silicon
(M1/M2) hosts this assertion was observed to fire for MIPS guest code. The
assertion is disabled with a comment explaining the reasoning:

```c
// Unicorn Hack (wtdcode):
// I have no clue about this assert and it seems the logic here is same with QEMU at least 7.2.1
// That said, qemu probably suffers the same issue but maybe no one emulates mips on M1?
// Disabling this still passes all unit tests so let's go with it.
// tcg_debug_assert(is_limm(limm));
```

---

## 5. Allowing All x86 I/O Instructions Unconditionally

**File:** `qemu/target/i386/translate.c:748`

QEMU enforces privilege checks for x86 I/O port instructions (`IN`/`OUT`) when
protected mode is active. Because Unicorn is a bare-metal CPU emulator with no
operating system layer, these checks are meaningless and would block valid guest
code. The entire `gen_check_io` function is short-circuited with an early return:

```c
static void gen_check_io(DisasContext *s, MemOp ot, target_ulong cur_eip,
                         uint32_t svm_flags)
{
    // Unicorn: allow all I/O instructions
    return;
    ...
```

---

## 6. Doubling `TCG_MAX_TEMPS` on 32-bit Hosts

**File:** `qemu/include/tcg/tcg.h:280`

Unicorn's inline instrumentation (e.g. memory and instruction hooks) generates
extra TCG temporaries. On 32-bit host builds this exhausts the default limit of 512
temporaries and causes a segfault. The limit is doubled on 32-bit targets:

```c
#if HOST_LONG_BITS == 32
// Unicorn: On 32 bits targets, our instrumentation uses extra temps and
//          thus could exhaust the max temps and cause segment fault.
//          Double the limit on 32 bits targets to avoid this.
#define TCG_MAX_TEMPS 1024
#else
#define TCG_MAX_TEMPS 512
#endif
```

---

## 7. Suppressing TCG Basic-Block-End Register-Spill Logic

**File:** `qemu/tcg/tcg.c:3106`

QEMU's register allocator saves all live local temporaries at the end of every
basic block. Unicorn inserts conditional-branch instructions (`brcond`) in the
*middle* of a translation block (to implement instruction-count limits and
`uc_emu_stop`) which violates this assumption. The spill loop is therefore
commented out entirely:

```c
// Unicorn: We are inserting brcond in the middle of the TB so the
//          assumptions here won't be satisfied.
// for (i = s->nb_globals; i < s->nb_temps; i++) { ... }
```

---

## 8. Forcing an Initial TCG Region Allocation

**File:** `qemu/tcg/tcg.c:541`

QEMU normally performs the first TCG region allocation lazily (in
`CONFIG_USER_ONLY` builds only). Without an explicit initial allocation,
`tcg_ctx->region.current` stays zero and a subsequent `tb_flush` may miss the
buffer-full condition. Unicorn always performs this allocation at startup:

```c
// Unicorn: Though this code is taken from CONFIG_USER_ONLY, it is crucial or
//          tcg_ctx->region.current is 0 and we will miss a tb_flush when the
//          buffer gets full.
{
    bool err = tcg_region_initial_alloc__locked(tcg_ctx);
    g_assert(!err);
}
```

---

## 9. `exit - 1` Address Adjustment When Invalidating Exit TBs

**File:** `qemu/softmmu/cpus.c:192`

When Unicorn invalidates translation blocks for registered exit addresses it
subtracts 1 from the exit address before calling `uc_invalidate_tb`. This is
necessary because `tb_invalidate_phys_range` operates on the half-open interval
`[start, end)`, so for a single-byte exit at address `N` the range `[N-1, N-1+1)`
correctly covers that byte:

```c
// Unicorn: Why addr - 1?
//
// 0: INC ecx
// 1: DEC edx <--- We put exit here, then the range of TB is [0, 1)
//
// While tb_invalidate_phys_range invalides [start, end)
uc->uc_invalidate_tb(uc, exit - 1, 1);
```

---

## Summary

| # | Location | Description |
|---|----------|-------------|
| 1 | `qemu/softmmu/memory.c`, `uc.c` | Integer snapshot level stored in `MemoryRegion::container` pointer |
| 2 | `qemu/accel/tcg/translate-all.c` | PC overridden with explicit `addr` inside `tb_find` |
| 3 | `qemu/target/arm/cpu.h`, `cpu.c` | ARM BE32 support: disabled feature check + changed `bswap_code` return value |
| 4 | `qemu/tcg/aarch64/tcg-target.inc.c` | `is_limm` assertion disabled for MIPS-on-AArch64 host |
| 5 | `qemu/target/i386/translate.c` | All x86 I/O privilege checks bypassed |
| 6 | `qemu/include/tcg/tcg.h` | `TCG_MAX_TEMPS` doubled on 32-bit hosts |
| 7 | `qemu/tcg/tcg.c` | BB-end temporary spill loop disabled |
| 8 | `qemu/tcg/tcg.c` | Forced initial TCG region allocation |
| 9 | `qemu/softmmu/cpus.c` | Exit-TB invalidation uses `exit - 1` address |
