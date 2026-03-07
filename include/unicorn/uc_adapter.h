/**
 * uc_adapter.h — Unicorn API → Adapter Layer → QEMU
 *
 * This header is the public surface of the adapter layer.  Callers include
 * only this file; all QEMU-internal types (uc_struct, UnicornVM,
 * MemoryRegion …) are available through the transitive include of uc_priv.h.
 *
 * Layering contract
 * -----------------
 *
 *   Caller code
 *       ↓  uca_* functions declared here
 *   uc_adapter.c  ←─ single QEMU isolation boundary
 *       ↓  uc_struct function pointers (memory_map, write_mem, …)
 *   QEMU (softmmu/memory.c, exec.c, TCG arch backends)
 *
 * When Unicorn is refactored to use upstream QEMU, only uc_adapter.c
 * needs to be updated — this header and all callers stay unchanged.
 *
 * Subsystems
 * ----------
 *   uca_mem_*      Memory mapping, read, write, protection.
 *   uca_hook_*     Typed hook registration (code, block, mem, I/O, intr).
 *   uca_snapshot_* Full-state snapshots (CPU registers + CoW memory).
 *   uca_intr_*     Per-interrupt-number dispatch table.
 */

#ifndef UNICORN_UC_ADAPTER_H
#define UNICORN_UC_ADAPTER_H

/*
 * Include the internal private header so that:
 *  - the UnicornVM typedef is visible (used throughout the implementation)
 *  - callers that include uc_adapter.h get the full uc_struct definition
 *    without having to include uc_priv.h separately
 */
#include "uc_priv.h"

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * Memory mapping
 * ========================================================================= */

/**
 * Map an anonymous RAM region.
 * @address and @size must be non-zero multiples of the engine's page size
 * (usually 4096).  @perms is a bitmask of UC_PROT_READ/WRITE/EXEC.
 */
uc_err uca_mem_map(uc_engine *uc, uint64_t address, uint64_t size,
                   uint32_t perms);

/**
 * Map a host-backed RAM region.
 * @ptr must remain valid for the lifetime of the mapping.
 */
uc_err uca_mem_map_ptr(uc_engine *uc, uint64_t address, uint64_t size,
                       uint32_t perms, void *ptr);

/**
 * Map a memory-mapped I/O region.
 * Either callback may be NULL if that access direction is unused.
 */
uc_err uca_mmio_map(uc_engine *uc, uint64_t address, uint64_t size,
                    uc_cb_mmio_read_t  read_cb,  void *user_data_read,
                    uc_cb_mmio_write_t write_cb, void *user_data_write);

/** Unmap a region previously created by uca_mem_map*(). */
uc_err uca_mem_unmap(uc_engine *uc, uint64_t address, uint64_t size);

/** Change protection flags on an existing mapping. */
uc_err uca_mem_protect(uc_engine *uc, uint64_t address, uint64_t size,
                       uint32_t perms);

/** Read @size bytes from emulated memory at @address into @buf. */
uc_err uca_mem_read(uc_engine *uc, uint64_t address, void *buf,
                    uint64_t size);

/** Write @size bytes from @buf into emulated memory at @address. */
uc_err uca_mem_write(uc_engine *uc, uint64_t address, const void *buf,
                     uint64_t size);


/* =========================================================================
 * Hooks
 * ========================================================================= */

/**
 * Remove a hook previously registered through any uca_hook_* function.
 * Safe to call from within a hook callback (lazy deletion).
 */
uc_err uca_hook_del(uc_engine *uc, uc_hook hh);

/**
 * Trace every instruction in [@begin, @end].
 * Pass begin=1, end=0 to hook all addresses (begin > end = always fire).
 */
uc_err uca_hook_code(uc_engine *uc, uc_hook *hh,
                     uc_cb_hookcode_t cb, void *user_data,
                     uint64_t begin, uint64_t end);

/** Fire at the first instruction of each basic block in [@begin, @end]. */
uc_err uca_hook_block(uc_engine *uc, uc_hook *hh,
                      uc_cb_hookcode_t cb, void *user_data,
                      uint64_t begin, uint64_t end);

/** Hook successful reads touching [@begin, @end] (before the read). */
uc_err uca_hook_mem_read(uc_engine *uc, uc_hook *hh,
                         uc_cb_hookmem_t cb, void *user_data,
                         uint64_t begin, uint64_t end);

/** Hook successful reads touching [@begin, @end] (after the read). */
uc_err uca_hook_mem_read_after(uc_engine *uc, uc_hook *hh,
                               uc_cb_hookmem_t cb, void *user_data,
                               uint64_t begin, uint64_t end);

/** Hook successful writes touching [@begin, @end]. */
uc_err uca_hook_mem_write(uc_engine *uc, uc_hook *hh,
                          uc_cb_hookmem_t cb, void *user_data,
                          uint64_t begin, uint64_t end);

/** Hook code fetches from [@begin, @end]. */
uc_err uca_hook_mem_fetch(uc_engine *uc, uc_hook *hh,
                          uc_cb_hookmem_t cb, void *user_data,
                          uint64_t begin, uint64_t end);

/**
 * Hook all invalid memory accesses (unmapped or permission faults).
 * Return true from the callback to continue execution (requires the handler
 * to fix the access); return false to stop with the appropriate UC_ERR_*.
 */
uc_err uca_hook_mem_invalid(uc_engine *uc, uc_hook *hh,
                            uc_cb_eventmem_t cb, void *user_data);

/** Hook all interrupts / exceptions (UC_HOOK_INTR). */
uc_err uca_hook_intr(uc_engine *uc, uc_hook *hh,
                     uc_cb_hookintr_t cb, void *user_data);

/**
 * Hook x86 IN instructions (port-I/O read).
 * Callback must return the 8/16/32-bit value read from the port.
 */
uc_err uca_hook_insn_io_in(uc_engine *uc, uc_hook *hh,
                           uc_cb_insn_in_t cb, void *user_data);

/** Hook x86 OUT instructions (port-I/O write). */
uc_err uca_hook_insn_io_out(uc_engine *uc, uc_hook *hh,
                            uc_cb_insn_out_t cb, void *user_data);

/**
 * Hook invalid instructions.
 * Return true to skip and continue; false to stop with UC_ERR_INSN_INVALID.
 */
uc_err uca_hook_insn_invalid(uc_engine *uc, uc_hook *hh,
                             uc_cb_hookinsn_invalid_t cb, void *user_data);


/* =========================================================================
 * Snapshots
 * ========================================================================= */

/**
 * Opaque snapshot handle.
 *
 * Captures CPU register state and emulated memory (via QEMU CoW).
 * The handle is caller-owned and must be released with uca_snapshot_free().
 */
typedef struct uca_snapshot uca_snapshot;

/**
 * Capture the current CPU and memory state.
 * On success *@out is set to a new uca_snapshot.
 * The snapshot can be restored any number of times.
 */
uc_err uca_snapshot_take(uc_engine *uc, uca_snapshot **out);

/**
 * Restore CPU and memory state from @snap.
 * The snapshot remains valid after the call.
 */
uc_err uca_snapshot_restore(uc_engine *uc, uca_snapshot *snap);

/** Free the snapshot and all resources it holds. NULL is a no-op. */
void uca_snapshot_free(uca_snapshot *snap);


/* =========================================================================
 * Context save / restore (fine-grained, caller-allocated uc_context)
 *
 * These mirror the public uc_context_save / uc_context_restore signatures
 * but delegate every QEMU boundary crossing through the adapter so that
 * only uc_adapter.c needs updating when QEMU internals change.
 *
 * Behaviour is controlled by uc->context_content (UC_CTL_CONTEXT_MEMORY
 * and/or UC_CTL_CONTEXT_CPU flags) exactly as the original functions.
 * ========================================================================= */

/** Save CPU and/or memory state into a caller-allocated context. */
uc_err uca_context_save(uc_engine *uc, uc_context *context);

/** Restore CPU and/or memory state from a caller-allocated context. */
uc_err uca_context_restore(uc_engine *uc, uc_context *context);


/* =========================================================================
 * Hook add — typed dispatch helpers
 *
 * These are called from uc_hook_add() after vararg extraction so that the
 * QEMU-touching implementation lives entirely in uc_adapter.c.
 * ========================================================================= */

/** Hook a specific instruction (UC_HOOK_INSN).  @insn_id is the arch insn. */
uc_err uca_hook_add_insn(uc_engine *uc, uc_hook *hh,
                         void *callback, void *user_data,
                         uint64_t begin, uint64_t end, int insn_id);

/** Hook a TCG opcode (UC_HOOK_TCG_OPCODE). */
uc_err uca_hook_add_tcg_opcode(uc_engine *uc, uc_hook *hh,
                                void *callback, void *user_data,
                                uint64_t begin, uint64_t end,
                                int op, int op_flags);

/**
 * Register a hook for a generic multi-bit @type mask (any UC_HOOK_* except
 * UC_HOOK_INSN and UC_HOOK_TCG_OPCODE, which require extra typed args).
 */
uc_err uca_hook_add_type(uc_engine *uc, uc_hook *hh, int type,
                         void *callback, void *user_data,
                         uint64_t begin, uint64_t end);


/* =========================================================================
 * Virtual-address memory access (goes through arch MMU translation)
 * ========================================================================= */

/** Translate a virtual @address of access type @prot to physical @*paddress. */
uc_err uca_vmem_translate(uc_engine *uc, uint64_t address, uc_prot prot,
                           uint64_t *paddress);

/** Read @size bytes through the arch MMU starting at virtual @address. */
uc_err uca_vmem_read(uc_engine *uc, uint64_t address, uc_prot prot,
                      void *buf, size_t size);

/** Write @size bytes through the arch MMU starting at virtual @address. */
uc_err uca_vmem_write(uc_engine *uc, uint64_t address, uc_prot prot,
                       void *buf, size_t size);


/* =========================================================================
 * TCG translated-block and TLB control
 * ========================================================================= */

/** Invalidate translated blocks covering [addr, addr+len). */
uc_err uca_tb_invalidate(uc_engine *uc, uint64_t addr, uint64_t len);

/** Discard all translated blocks. */
void uca_tb_flush(uc_engine *uc);

/** Flush the software TLB. */
void uca_tlb_flush(uc_engine *uc);

/** Switch TLB implementation to @mode. */
uc_err uca_tlb_set_type(uc_engine *uc, int mode);

/** JIT-compile one translation block at @addr and return its descriptor. */
uc_err uca_tb_request(uc_engine *uc, uint64_t addr, uc_tb *out_tb);


/* =========================================================================
 * Context allocation helpers
 * ========================================================================= */

/** Return the total byte size of a uc_context for this engine. */
size_t uca_context_size(uc_engine *uc);

/** Allocate and zero-initialise a uc_context for this engine. */
uc_err uca_context_alloc(uc_engine *uc, uc_context **context);


/* =========================================================================
 * Memory region enumeration
 * ========================================================================= */

/**
 * Return an array of all currently mapped regions.
 * The caller frees *@regions with uc_free().
 */
uc_err uca_mem_regions(uc_engine *uc, uc_mem_region **regions,
                        uint32_t *count);


/* =========================================================================
 * Engine lifecycle
 * ========================================================================= */

/**
 * Allocate and zero-initialise a fresh uc_struct.
 * Sets arch, mode, and default reg_read/reg_write stubs.
 * Does NOT call machine_initialize — that happens lazily on first use.
 */
uc_err uca_engine_alloc(uc_arch arch, uc_mode mode, uc_engine **out);

/**
 * Initialise the QEMU backend for an already-allocated engine.
 * Called once, lazily, on first API use.  Idiomatic callers use UC_INIT.
 */
uc_err uca_engine_init(uc_engine *uc);

/**
 * Tear down and free an engine created by uca_engine_alloc / uc_open.
 * If init was never completed, only the uc_struct itself is freed.
 */
uc_err uca_engine_close(uc_engine *uc);


/* =========================================================================
 * Register read / write
 * ========================================================================= */

uc_err uca_reg_read(uc_engine *uc, int regid, void *value);
uc_err uca_reg_write(uc_engine *uc, int regid, const void *value);
uc_err uca_reg_read2(uc_engine *uc, int regid, void *value, size_t *size);
uc_err uca_reg_write2(uc_engine *uc, int regid, const void *value,
                      size_t *size);
uc_err uca_reg_read_batch(uc_engine *uc, int const *regs, void **vals,
                          int count);
uc_err uca_reg_write_batch(uc_engine *uc, int const *regs,
                           void *const *vals, int count);
uc_err uca_reg_read_batch2(uc_engine *uc, int const *regs, void *const *vals,
                           size_t *sizes, int count);
uc_err uca_reg_write_batch2(uc_engine *uc, int const *regs,
                            const void *const *vals, size_t *sizes, int count);


/* =========================================================================
 * Emulation control
 * ========================================================================= */

/**
 * Start emulation at @begin, stopping at @until (or via exits/hooks).
 * @timeout is in microseconds (0 = no limit).  @count limits instruction
 * count (0 = unlimited).
 */
uc_err uca_emu_start(uc_engine *uc, uint64_t begin, uint64_t until,
                     uint64_t timeout, size_t count);

/** Request the emulation loop to stop at the next safe point. */
uc_err uca_emu_stop(uc_engine *uc);


/* =========================================================================
 * Query
 * ========================================================================= */

uc_err uca_query(uc_engine *uc, uc_query_type type, size_t *result);


/* =========================================================================
 * Interrupt router
 * ========================================================================= */

/**
 * Per-interrupt handler callback.
 * @intno     — the interrupt/exception number that fired.
 * @user_data — value supplied to uca_intr_register().
 */
typedef void (*uca_intr_handler_t)(uc_engine *uc, uint32_t intno,
                                   void *user_data);

/**
 * Opaque interrupt dispatch table.
 *
 * Installs one UC_HOOK_INTR hook into uc->unicorn.hook[UC_HOOK_INTR_IDX]
 * and routes each interrupt number to the matching registered handler.
 * Unregistered interrupts are silently ignored.
 */
typedef struct uca_intr_router uca_intr_router;

/**
 * Create an interrupt router and attach it to @uc.
 * On success *@out is set to a new uca_intr_router.
 * Must be freed with uca_intr_router_free() before the engine is closed.
 */
uc_err uca_intr_router_create(uc_engine *uc, uca_intr_router **out);

/**
 * Register @handler for interrupt number @intno.
 * Replaces any previously registered handler for @intno.
 */
uc_err uca_intr_register(uca_intr_router *router, uint32_t intno,
                         uca_intr_handler_t handler, void *user_data);

/** Remove the handler for @intno. No-op if none is registered. */
void uca_intr_unregister(uca_intr_router *router, uint32_t intno);

/**
 * Remove the hook, free all handlers, and free the router.
 * NULL is a no-op.
 */
void uca_intr_router_free(uc_engine *uc, uca_intr_router *router);


#ifdef __cplusplus
}
#endif

#endif /* UNICORN_UC_ADAPTER_H */
