/**
 * uc_adapter.c — Unicorn API → Adapter Layer → QEMU
 *
 * This file is the single QEMU isolation boundary.
 * Every call that reaches QEMU's internal memory or CPU machinery goes
 * through a uc_struct function pointer and is marked [QEMU boundary].
 * When Unicorn is refactored to use upstream QEMU, only this file changes.
 *
 * Architecture
 * ------------
 *  Caller code
 *      ↓  uca_* functions (this file)
 *  uc_struct function pointers  ← QEMU boundary (all crossings marked below)
 *      ↓
 *  QEMU (exec.c, softmmu/memory.c, TCG, arch backends)
 *
 * Subsystems
 * ----------
 *  Memory:     uca_mem_*   — allocation, r/w, protection, unmap.
 *              All MemoryRegion allocation/deallocation goes through
 *              uc->memory_map / uc->memory_unmap / uc->write_mem etc.
 *              UnicornVM.mapped_blocks[] bookkeeping is managed here.
 *
 *  Hooks:      uca_hook_*  — inserts struct hook directly into
 *              UnicornVM.hook[] lists.  TCG fires hooks through those lists.
 *
 *  Snapshots:  uca_snapshot_* — CPU state via uc->context_save/restore;
 *              memory state via uc->flatview_copy + CoW snapshot_level.
 *
 *  Interrupts: uca_intr_*  — single UC_HOOK_INTR_IDX hook that routes each
 *              interrupt number to a registered handler.
 */

#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Internal headers — exposes uc_struct, UnicornVM, MemoryRegion, FlatView,
 * GArray, QTAILQ macros, and the full hook/list infrastructure. */
#include "uc_priv.h"

#include "unicorn/uc_adapter.h"
#include "unicorn/x86.h"   /* UC_X86_INS_IN, UC_X86_INS_OUT */

/* Forward declarations to allow mutual recursion between split helpers and
 * uca_mem_unmap.  The split helpers are defined in the memory section below. */
static bool ucadapt_split_region(struct uc_struct *uc, MemoryRegion *mr,
                                  uint64_t address, uint64_t size,
                                  bool do_delete);
static bool ucadapt_split_mmio_region(struct uc_struct *uc, MemoryRegion *mr,
                                       uint64_t address, uint64_t size,
                                       bool do_delete);


/* =========================================================================
 * Internal helpers — mapped_blocks bookkeeping
 *
 * These mirror the static helpers in uc.c.  When uc.c is eventually
 * replaced by adapter calls the duplication will be removed.
 *
 * NOTE: uc->memory_unmap (QEMU boundary) automatically removes the region
 * from mapped_blocks via memory_region_remove_mapped_block() inside
 * qemu/softmmu/memory.c.  ucadapt_mem_track() is therefore only called
 * when *adding* a newly allocated region.
 * ========================================================================= */

/* Return insertion index for address in the sorted mapped_blocks array. */
static int ucadapt_bsearch(const uc_engine *uc, uint64_t address)
{
    int left = 0, right = (int)uc->unicorn.mapped_block_count;
    while (left < right) {
        int mid = left + (right - left) / 2;
        MemoryRegion *mr = uc->unicorn.mapped_blocks[mid];
        if (mr->end - 1 < address)
            left = mid + 1;
        else if (mr->addr > address)
            right = mid;
        else
            return mid;
    }
    return left;
}

/* True if [begin, begin+size) overlaps any entry in mapped_blocks. */
static bool ucadapt_overlaps(struct uc_struct *uc, uint64_t begin, size_t size)
{
    uint64_t end = begin + size - 1;
    unsigned int i = (unsigned int)ucadapt_bsearch(uc, begin);
    if (i >= uc->unicorn.mapped_block_count)
        return false;
    return end >= uc->unicorn.mapped_blocks[i]->addr;
}

/* Insert *block into the sorted mapped_blocks array. */
static uc_err ucadapt_mem_track(uc_engine *uc, MemoryRegion *block)
{
    if (!block)
        return UC_ERR_NOMEM;

    if ((uc->unicorn.mapped_block_count & (MEM_BLOCK_INCR - 1)) == 0) {
        MemoryRegion **r = (MemoryRegion **)g_realloc(
            uc->unicorn.mapped_blocks,
            sizeof(MemoryRegion *) *
                (uc->unicorn.mapped_block_count + MEM_BLOCK_INCR));
        if (!r)
            return UC_ERR_NOMEM;
        uc->unicorn.mapped_blocks = r;
    }

    int pos = ucadapt_bsearch(uc, block->addr);
    memmove(&uc->unicorn.mapped_blocks[pos + 1],
            &uc->unicorn.mapped_blocks[pos],
            sizeof(MemoryRegion *) * (uc->unicorn.mapped_block_count - pos));
    uc->unicorn.mapped_blocks[pos] = block;
    uc->unicorn.mapped_block_count++;
    return UC_ERR_OK;
}

/* Validate address/size alignment and permissions, check for overlap. */
static uc_err ucadapt_map_check(uc_engine *uc, uint64_t address,
                                uint64_t size, uint32_t perms)
{
    if (size == 0 || (address + size - 1 < address))
        return UC_ERR_ARG;
    if (address & uc->target_page_align)
        return UC_ERR_ARG;
    if (size & uc->target_page_align)
        return UC_ERR_ARG;
    if (perms & ~UC_PROT_ALL)
        return UC_ERR_ARG;
    if (ucadapt_overlaps(uc, address, (size_t)size))
        return UC_ERR_MAP;
    return UC_ERR_OK;
}

/* Bytes available in *mr starting from address, capped at size. */
static uint64_t ucadapt_region_len(uc_engine *uc, MemoryRegion *mr,
                                   uint64_t address, uint64_t size)
{
    hwaddr end = mr->end;
    while (mr->container != uc->system_memory) {
        mr = mr->container;
        end += mr->addr;
    }
    return (uint64_t)MIN(size, end - address);
}

/* True if the entire [address, address+size) span is currently mapped. */
static bool ucadapt_is_mapped(uc_engine *uc, uint64_t address, size_t size)
{
    size_t count = 0, len;
    while (count < size) {
        /* QEMU boundary: locate the MemoryRegion covering address */
        MemoryRegion *mr = uc->memory_mapping(uc, address);
        if (!mr)
            break;
        len = (size_t)ucadapt_region_len(uc, mr, address, size - count);
        count   += len;
        address += len;
    }
    return count == size;
}


/* =========================================================================
 * Internal hook placement helper — respects UnicornVM.hook_insert flag.
 *
 * When hook_insert is set (uc_emu_start priority path) list_insert places
 * the hook at the front; otherwise list_append places it at the back.
 * Returns false on OOM; bumps hk->refs and hooks_count on success.
 * ========================================================================= */
static bool ucadapt_hook_place_slot(uc_engine *uc, uc_hook_idx idx,
                                     struct hook *hk)
{
    bool ok = uc->unicorn.hook_insert
        ? (list_insert(&uc->unicorn.hook[idx], hk) != NULL)
        : (list_append(&uc->unicorn.hook[idx], hk) != NULL);
    if (ok) {
        hk->refs++;
        uc->unicorn.hooks_count[idx]++;
    }
    return ok;
}


/* =========================================================================
 * Region-split helpers
 *
 * These match the logic of split_region / split_mmio_region in uc.c but
 * call uca_* functions (not the public uc_* API) to stay inside the
 * adapter boundary and avoid the UC_INIT / restore_jit_state overhead.
 *
 * The helpers are forward-declared at the top of this file to resolve the
 * mutual recursion: uca_mem_unmap → ucadapt_split_* → uca_mem_unmap.
 * ========================================================================= */

/* Back-up the raw bytes of *mr by reading them through the adapter. */
static uint8_t *ucadapt_copy_region(uc_engine *uc, MemoryRegion *mr)
{
    uint64_t sz = (uint64_t)int128_get64(mr->size);
    uint8_t *block = (uint8_t *)g_malloc0(sz);
    if (block &&
        uca_mem_read(uc, mr->addr, block, sz) != UC_ERR_OK) {
        g_free(block);
        block = NULL;
    }
    return block;
}

/*
 * Split a RAM-backed MemoryRegion around [address, address+size).
 * If do_delete is true the middle chunk is not re-mapped (deletion path).
 * Called recursively via uca_mem_unmap.
 */
static bool ucadapt_split_region(struct uc_struct *uc, MemoryRegion *mr,
                                  uint64_t address, uint64_t size,
                                  bool do_delete)
{
    uint8_t   *backup;
    uint32_t   perms;
    uint64_t   begin, end, chunk_end;
    uint64_t   l_size, m_size, r_size;
    RAMBlock  *block = NULL;
    bool       prealloc = false;

    chunk_end = address + size;

    /* Region is fully covered — nothing to split. */
    if (address <= mr->addr && chunk_end >= mr->end)
        return true;
    if (size == 0)
        return true;
    if (address >= mr->end || chunk_end <= mr->addr)
        return false;

    block = mr->ram_block;
    if (!block)
        return false;

    /* RAM_PREALLOC flag (bit 0) means the host buffer is caller-owned. */
    prealloc = !!(block->flags & 1);

    if (prealloc) {
        backup = block->host;
    } else {
        backup = ucadapt_copy_region(uc, mr);
        if (!backup)
            return false;
    }

    perms = mr->perms;
    begin = mr->addr;
    end   = mr->end;

    /* QEMU boundary: remove the original region before re-splitting */
    if (uca_mem_unmap(uc, mr->addr, (uint64_t)int128_get64(mr->size)) != UC_ERR_OK)
        goto error;

    if (address   < begin) address   = begin;
    if (chunk_end > end)   chunk_end = end;

    l_size = address   - begin;
    r_size = end       - chunk_end;
    m_size = chunk_end - address;

    if (l_size > 0) {
        if (!prealloc) {
            if (uca_mem_map(uc, begin, l_size, perms) != UC_ERR_OK) goto error;
            if (uca_mem_write(uc, begin, backup, l_size) != UC_ERR_OK) goto error;
        } else {
            if (uca_mem_map_ptr(uc, begin, l_size, perms, backup) != UC_ERR_OK)
                goto error;
        }
    }

    if (m_size > 0 && !do_delete) {
        if (!prealloc) {
            if (uca_mem_map(uc, address, m_size, perms) != UC_ERR_OK) goto error;
            if (uca_mem_write(uc, address, backup + l_size, m_size) != UC_ERR_OK)
                goto error;
        } else {
            if (uca_mem_map_ptr(uc, address, m_size, perms, backup + l_size) != UC_ERR_OK)
                goto error;
        }
    }

    if (r_size > 0) {
        if (!prealloc) {
            if (uca_mem_map(uc, chunk_end, r_size, perms) != UC_ERR_OK) goto error;
            if (uca_mem_write(uc, chunk_end, backup + l_size + m_size, r_size) != UC_ERR_OK)
                goto error;
        } else {
            if (uca_mem_map_ptr(uc, chunk_end, r_size, perms,
                                backup + l_size + m_size) != UC_ERR_OK)
                goto error;
        }
    }

    if (!prealloc) g_free(backup);
    return true;

error:
    if (!prealloc) g_free(backup);
    return false;
}

/*
 * Split an MMIO MemoryRegion around [address, address+size).
 * Mirrors split_mmio_region() from uc.c.  May call itself recursively.
 */
static bool ucadapt_split_mmio_region(struct uc_struct *uc, MemoryRegion *mr,
                                       uint64_t address, uint64_t size,
                                       bool do_delete)
{
    uint64_t begin, end, chunk_end;
    uint64_t l_size, r_size, m_size;
    mmio_cbs backup;

    chunk_end = address + size;

    /* Region fully covered — nothing to split. */
    if (address <= mr->addr && chunk_end >= mr->end)
        return true;
    if (size == 0)
        return false;

    begin = mr->addr;
    end   = mr->end;

    memcpy(&backup, mr->opaque, sizeof(mmio_cbs));

    /* QEMU boundary: remove original MMIO region first */
    if (uca_mem_unmap(uc, mr->addr, (uint64_t)int128_get64(mr->size)) != UC_ERR_OK)
        return false;

    if (address   < begin) address   = begin;
    if (chunk_end > end)   chunk_end = end;

    l_size = address   - begin;
    r_size = end       - chunk_end;
    m_size = chunk_end - address;

    if (l_size > 0) {
        if (uca_mmio_map(uc, begin, l_size,
                         backup.read,  backup.user_data_read,
                         backup.write, backup.user_data_write) != UC_ERR_OK)
            return false;
    }

    if (m_size > 0 && !do_delete) {
        if (uca_mmio_map(uc, address, m_size,
                         backup.read,  backup.user_data_read,
                         backup.write, backup.user_data_write) != UC_ERR_OK)
            return false;
    }

    if (r_size > 0) {
        if (uca_mmio_map(uc, chunk_end, r_size,
                         backup.read,  backup.user_data_read,
                         backup.write, backup.user_data_write) != UC_ERR_OK)
            return false;
    }

    return true;
}


/* =========================================================================
 * Memory mapping — QEMU boundary
 *
 * Every MemoryRegion allocation/deallocation is performed through the
 * uc_struct function pointers so that swapping in upstream QEMU only
 * requires updating those function-pointer implementations.
 * ========================================================================= */

uc_err uca_mem_map(uc_engine *uc, uint64_t address, uint64_t size,
                   uint32_t perms)
{
    uc_err err = ucadapt_map_check(uc, address, size, perms);
    if (err)
        return err;
    /* QEMU boundary: allocates a RAM-backed MemoryRegion in QEMU's graph */
    return ucadapt_mem_track(uc, uc->memory_map(uc, address, size, perms));
}

uc_err uca_mem_map_ptr(uc_engine *uc, uint64_t address, uint64_t size,
                       uint32_t perms, void *ptr)
{
    if (!ptr)
        return UC_ERR_ARG;
    uc_err err = ucadapt_map_check(uc, address, size, perms);
    if (err)
        return err;
    /* QEMU boundary: backs the region with caller-supplied host memory */
    return ucadapt_mem_track(
        uc, uc->memory_map_ptr(uc, address, size, perms, ptr));
}

uc_err uca_mmio_map(uc_engine *uc, uint64_t address, uint64_t size,
                    uc_cb_mmio_read_t  read_cb,  void *user_data_read,
                    uc_cb_mmio_write_t write_cb, void *user_data_write)
{
    uc_err err = ucadapt_map_check(uc, address, size, UC_PROT_ALL);
    if (err)
        return err;
    /* QEMU boundary: registers MMIO callbacks in QEMU's MemoryRegion graph */
    return ucadapt_mem_track(
        uc, uc->memory_map_io(uc, address, size,
                              read_cb,  write_cb,
                              user_data_read, user_data_write));
}

uc_err uca_mem_unmap(uc_engine *uc, uint64_t address, uint64_t size)
{
    uint64_t addr = address, count = 0, len;

    if (size == 0)
        return UC_ERR_OK;
    if (address & uc->target_page_align)
        return UC_ERR_ARG;
    if (size & uc->target_page_align)
        return UC_ERR_ARG;
    if (!ucadapt_is_mapped(uc, address, (size_t)size))
        return UC_ERR_NOMEM;

    if (uc->unicorn.snapshot_level > 0) {
        /* Inside a CoW snapshot: move the region out without freeing it. */
        /* QEMU boundary: walk to top-level region in system_memory */
        MemoryRegion *mr = uc->memory_mapping(uc, address);
        while (mr && mr->container != uc->system_memory)
            mr = mr->container;
        if (!mr || mr->addr != address ||
            (uint64_t)int128_get64(mr->size) != size)
            return UC_ERR_ARG;
        /* QEMU boundary: detach from address space, save for later restore */
        uc->memory_moveout(uc, mr);
        return UC_ERR_OK;
    }

    while (count < size) {
        /* QEMU boundary: locate region covering addr */
        MemoryRegion *mr = uc->memory_mapping(uc, addr);
        if (!mr)
            break;
        len = ucadapt_region_len(uc, mr, addr, size - count);
        /* Split so that [addr, addr+len) becomes its own standalone region. */
        if (!mr->ram) {
            if (!ucadapt_split_mmio_region(uc, mr, addr, len, true))
                return UC_ERR_NOMEM;
        } else {
            if (!ucadapt_split_region(uc, mr, addr, len, true))
                return UC_ERR_NOMEM;
        }
        /* After splitting, re-look up the (now standalone) region and free it. */
        mr = uc->memory_mapping(uc, addr); /* QEMU boundary */
        if (mr != NULL)
            uc->memory_unmap(uc, mr);      /* QEMU boundary */
        count += len;
        addr  += len;
    }
    return UC_ERR_OK;
}

uc_err uca_mem_protect(uc_engine *uc, uint64_t address, uint64_t size,
                       uint32_t perms)
{
    uint64_t addr = address, count = 0, len;
    bool remove_exec = false;

    /* Permission changes cannot be mixed with CoW snapshots. */
    if (uc->unicorn.snapshot_level > 0)
        return UC_ERR_ARG;
    if (size == 0)
        return UC_ERR_OK;
    if (address & uc->target_page_align)
        return UC_ERR_ARG;
    if (size & uc->target_page_align)
        return UC_ERR_ARG;
    if (perms & ~UC_PROT_ALL)
        return UC_ERR_ARG;
    if (!ucadapt_is_mapped(uc, address, (size_t)size))
        return UC_ERR_NOMEM;

    while (count < size) {
        /* QEMU boundary: locate region */
        MemoryRegion *mr = uc->memory_mapping(uc, addr);
        len = ucadapt_region_len(uc, mr, addr, size - count);
        if (mr->ram) {
            if (!ucadapt_split_region(uc, mr, addr, len, false))
                return UC_ERR_NOMEM;
            /* QEMU boundary: re-look up after potential split */
            mr = uc->memory_mapping(uc, addr);
            if (((mr->perms & UC_PROT_EXEC) != 0) &&
                ((perms & UC_PROT_EXEC) == 0))
                remove_exec = true;
            mr->perms = perms;
            /* QEMU boundary: toggle QEMU write-protect flag */
            uc->readonly_mem(mr, (perms & UC_PROT_WRITE) == 0);
        } else {
            if (!ucadapt_split_mmio_region(uc, mr, addr, len, false))
                return UC_ERR_NOMEM;
            /* QEMU boundary: re-look up after potential split */
            mr = uc->memory_mapping(uc, addr);
            mr->perms = perms;
        }
        count += len;
        addr  += len;
    }

    /* If EXEC permission was removed, stop at current PC if inside range. */
    if (remove_exec) {
        /* QEMU boundary: read the current program counter */
        uint64_t pc = uc->get_pc(uc);
        if (pc >= address && pc < address + size) {
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }

    return UC_ERR_OK;
}


/* =========================================================================
 * Memory read / write — direct AddressSpace QEMU boundary calls
 * ========================================================================= */

uc_err uca_mem_read(uc_engine *uc, uint64_t address, void *buf, uint64_t size)
{
    uint64_t count = 0, len;
    uint8_t *p = (uint8_t *)buf;

    if (!ucadapt_is_mapped(uc, address, (size_t)size))
        return UC_ERR_READ_UNMAPPED;

    while (count < size) {
        /* QEMU boundary: find region */
        MemoryRegion *mr = uc->memory_mapping(uc, address);
        if (!mr)
            break;
        len = ucadapt_region_len(uc, mr, address, size - count);
        /* QEMU boundary: uc->read_mem == address_space_read */
        if (!uc->read_mem(&uc->address_space_memory, address, p, len))
            break;
        count   += len;
        address += len;
        p       += len;
    }
    return (count == size) ? UC_ERR_OK : UC_ERR_READ_UNMAPPED;
}

uc_err uca_mem_write(uc_engine *uc, uint64_t address, const void *buf,
                     uint64_t size)
{
    uint64_t count = 0, len;
    uint64_t align = uc->target_page_align;
    const uint8_t *p = (const uint8_t *)buf;

    if (!ucadapt_is_mapped(uc, address, (size_t)size))
        return UC_ERR_WRITE_UNMAPPED;

    while (count < size) {
        /* QEMU boundary: find region */
        MemoryRegion *mr = uc->memory_mapping(uc, address);
        if (!mr)
            break;

        uint32_t saved_perms = mr->perms;
        if (!(saved_perms & UC_PROT_WRITE))
            /* QEMU boundary: temporarily lift write-protect for host write */
            uc->readonly_mem(mr, false);

        len = ucadapt_region_len(uc, mr, address, size - count);

        /* CoW: if a snapshot is active, copy the page before writing so the
         * original page is preserved for later restore. */
        if (uc->unicorn.snapshot_level > 0 &&
            uc->unicorn.snapshot_level > mr->priority) {
            /* QEMU boundary: uc->memory_cow clones the backing RAMBlock */
            mr = uc->memory_cow(uc, mr,
                                address & ~align,
                                (len + (address & align) + align) & ~align);
            if (!mr)
                return UC_ERR_NOMEM;
        }

        /* QEMU boundary: uc->write_mem == address_space_write */
        if (!uc->write_mem(&uc->address_space_memory, address, p, len))
            break;

        if (!(saved_perms & UC_PROT_WRITE))
            /* QEMU boundary: restore write-protect */
            uc->readonly_mem(mr, true);

        count   += len;
        address += len;
        p       += len;
    }
    return (count == size) ? UC_ERR_OK : UC_ERR_WRITE_UNMAPPED;
}


/* =========================================================================
 * Hooks — direct UnicornVM hook list manipulation
 *
 * struct hook nodes are inserted directly into uc->unicorn.hook[idx] lists.
 * The QEMU TCG instruction decoder fires hook callbacks by walking those
 * lists (see helper_uc_tracecode in uc.c and the generated TCG code).
 *
 * GHashTable *hooked_regions tracks which TBs have been instrumented so
 * that hook deletion can invalidate the right translated blocks.
 * ========================================================================= */

/* Invalidate one TB region when a hook is deleted. */
static void ucadapt_invalidate_region(void *key, void *data, void *opaq)
{
    uc_engine *uc = (uc_engine *)opaq;
    HookedRegion *region = (HookedRegion *)key;
    /* QEMU boundary: invalidate TCG translation blocks covering [start, len) */
    uc->uc_invalidate_tb(uc, region->start, region->length);
}

/* Allocate and zero-initialise a struct hook node. */
static struct hook *ucadapt_alloc_hook(void *callback, void *user_data,
                                       uint64_t begin, uint64_t end)
{
    struct hook *hk = calloc(1, sizeof(*hk));
    if (!hk)
        return NULL;
    hk->begin     = begin;
    hk->end       = end;
    hk->callback  = callback;
    hk->user_data = user_data;
    hk->refs      = 0;
    hk->to_delete = false;
    hk->hooked_regions = g_hash_table_new_full(
        hooked_regions_hash, hooked_regions_equal, g_free, NULL);
    return hk;
}

/* Append hk into uc->unicorn.hook[idx], bump ref-count and counter. */
static uc_err ucadapt_hook_append(uc_engine *uc, uc_hook *hh,
                                  uc_hook_idx idx, struct hook *hk)
{
    if (!ucadapt_hook_place_slot(uc, idx, hk)) {
        g_hash_table_destroy(hk->hooked_regions);
        free(hk);
        return UC_ERR_NOMEM;
    }
    *hh = (uc_hook)hk;
    return UC_ERR_OK;
}

uc_err uca_hook_del(uc_engine *uc, uc_hook hh)
{
    struct hook *hk = (struct hook *)hh;
    for (int i = 0; i < UC_HOOK_MAX; i++) {
        if (list_exists(&uc->unicorn.hook[i], hk)) {
            /* QEMU boundary: invalidate all TBs that were instrumented */
            g_hash_table_foreach(hk->hooked_regions,
                                 ucadapt_invalidate_region, uc);
            g_hash_table_remove_all(hk->hooked_regions);
            hk->to_delete = true;
            uc->unicorn.hooks_count[i]--;
            /* Lazy deletion: cleaned up at end of uc_emu_start() */
            list_append(&uc->unicorn.hooks_to_del, hk);
        }
    }
    return UC_ERR_OK;
}

uc_err uca_hook_code(uc_engine *uc, uc_hook *hh,
                     uc_cb_hookcode_t cb, void *user_data,
                     uint64_t begin, uint64_t end)
{
    struct hook *hk = ucadapt_alloc_hook(cb, user_data, begin, end);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = UC_HOOK_CODE;
    return ucadapt_hook_append(uc, hh, UC_HOOK_CODE_IDX, hk);
}

uc_err uca_hook_block(uc_engine *uc, uc_hook *hh,
                      uc_cb_hookcode_t cb, void *user_data,
                      uint64_t begin, uint64_t end)
{
    struct hook *hk = ucadapt_alloc_hook(cb, user_data, begin, end);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = UC_HOOK_BLOCK;
    return ucadapt_hook_append(uc, hh, UC_HOOK_BLOCK_IDX, hk);
}

uc_err uca_hook_mem_read(uc_engine *uc, uc_hook *hh,
                         uc_cb_hookmem_t cb, void *user_data,
                         uint64_t begin, uint64_t end)
{
    struct hook *hk = ucadapt_alloc_hook(cb, user_data, begin, end);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = UC_HOOK_MEM_READ;
    return ucadapt_hook_append(uc, hh, UC_HOOK_MEM_READ_IDX, hk);
}

uc_err uca_hook_mem_read_after(uc_engine *uc, uc_hook *hh,
                               uc_cb_hookmem_t cb, void *user_data,
                               uint64_t begin, uint64_t end)
{
    struct hook *hk = ucadapt_alloc_hook(cb, user_data, begin, end);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = UC_HOOK_MEM_READ_AFTER;
    return ucadapt_hook_append(uc, hh, UC_HOOK_MEM_READ_AFTER_IDX, hk);
}

uc_err uca_hook_mem_write(uc_engine *uc, uc_hook *hh,
                          uc_cb_hookmem_t cb, void *user_data,
                          uint64_t begin, uint64_t end)
{
    struct hook *hk = ucadapt_alloc_hook(cb, user_data, begin, end);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = UC_HOOK_MEM_WRITE;
    return ucadapt_hook_append(uc, hh, UC_HOOK_MEM_WRITE_IDX, hk);
}

uc_err uca_hook_mem_fetch(uc_engine *uc, uc_hook *hh,
                          uc_cb_hookmem_t cb, void *user_data,
                          uint64_t begin, uint64_t end)
{
    struct hook *hk = ucadapt_alloc_hook(cb, user_data, begin, end);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = UC_HOOK_MEM_FETCH;
    return ucadapt_hook_append(uc, hh, UC_HOOK_MEM_FETCH_IDX, hk);
}

uc_err uca_hook_mem_invalid(uc_engine *uc, uc_hook *hh,
                            uc_cb_eventmem_t cb, void *user_data)
{
    /* UC_HOOK_MEM_INVALID covers all six invalid-access hook slots.
     * begin=1, end=0 is the "always fire" sentinel (begin > end). */
    static const uc_hook_idx slots[] = {
        UC_HOOK_MEM_READ_UNMAPPED_IDX,  UC_HOOK_MEM_WRITE_UNMAPPED_IDX,
        UC_HOOK_MEM_FETCH_UNMAPPED_IDX, UC_HOOK_MEM_READ_PROT_IDX,
        UC_HOOK_MEM_WRITE_PROT_IDX,     UC_HOOK_MEM_FETCH_PROT_IDX,
    };
    struct hook *hk = ucadapt_alloc_hook(cb, user_data, 1, 0);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = UC_HOOK_MEM_INVALID;

    for (int i = 0; i < (int)(sizeof(slots) / sizeof(slots[0])); i++) {
        if (!list_append(&uc->unicorn.hook[slots[i]], hk)) {
            for (int j = 0; j < i; j++)
                list_remove(&uc->unicorn.hook[slots[j]], hk);
            g_hash_table_destroy(hk->hooked_regions);
            free(hk);
            return UC_ERR_NOMEM;
        }
        hk->refs++;
        uc->unicorn.hooks_count[slots[i]]++;
    }
    *hh = (uc_hook)hk;
    return UC_ERR_OK;
}

uc_err uca_hook_intr(uc_engine *uc, uc_hook *hh,
                     uc_cb_hookintr_t cb, void *user_data)
{
    struct hook *hk = ucadapt_alloc_hook(cb, user_data, 1, 0);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = UC_HOOK_INTR;
    return ucadapt_hook_append(uc, hh, UC_HOOK_INTR_IDX, hk);
}

uc_err uca_hook_insn_io_in(uc_engine *uc, uc_hook *hh,
                           uc_cb_insn_in_t cb, void *user_data)
{
    struct hook *hk = ucadapt_alloc_hook(cb, user_data, 1, 0);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = UC_HOOK_INSN;
    hk->insn = UC_X86_INS_IN;
    /* QEMU boundary: insn_hook_validate checks arch support via TCG tables */
    if (uc->insn_hook_validate && !uc->insn_hook_validate(hk->insn)) {
        g_hash_table_destroy(hk->hooked_regions);
        free(hk);
        return UC_ERR_HOOK;
    }
    return ucadapt_hook_append(uc, hh, UC_HOOK_INSN_IDX, hk);
}

uc_err uca_hook_insn_io_out(uc_engine *uc, uc_hook *hh,
                            uc_cb_insn_out_t cb, void *user_data)
{
    struct hook *hk = ucadapt_alloc_hook(cb, user_data, 1, 0);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = UC_HOOK_INSN;
    hk->insn = UC_X86_INS_OUT;
    /* QEMU boundary: insn_hook_validate checks arch support via TCG tables */
    if (uc->insn_hook_validate && !uc->insn_hook_validate(hk->insn)) {
        g_hash_table_destroy(hk->hooked_regions);
        free(hk);
        return UC_ERR_HOOK;
    }
    return ucadapt_hook_append(uc, hh, UC_HOOK_INSN_IDX, hk);
}

uc_err uca_hook_insn_invalid(uc_engine *uc, uc_hook *hh,
                             uc_cb_hookinsn_invalid_t cb, void *user_data)
{
    struct hook *hk = ucadapt_alloc_hook(cb, user_data, 1, 0);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = UC_HOOK_INSN_INVALID;
    return ucadapt_hook_append(uc, hh, UC_HOOK_INSN_INVALID_IDX, hk);
}


/* =========================================================================
 * uc_hook_add dispatch helpers — handle UC_HOOK_INSN, UC_HOOK_TCG_OPCODE,
 * and the generic type-bitmask case.  These are called from uc_hook_add()
 * in uc.c after the varargs have been extracted.
 *
 * All three paths respect uc->unicorn.hook_insert via ucadapt_hook_place_slot.
 * ========================================================================= */

uc_err uca_hook_add_insn(uc_engine *uc, uc_hook *hh,
                         void *callback, void *user_data,
                         uint64_t begin, uint64_t end, int insn_id)
{
    struct hook *hk = ucadapt_alloc_hook(callback, user_data, begin, end);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = UC_HOOK_INSN;
    hk->insn = insn_id;
    /* QEMU boundary: validate via arch TCG instruction table */
    if (uc->insn_hook_validate && !uc->insn_hook_validate(hk->insn)) {
        g_hash_table_destroy(hk->hooked_regions);
        free(hk);
        return UC_ERR_HOOK;
    }
    if (!ucadapt_hook_place_slot(uc, UC_HOOK_INSN_IDX, hk)) {
        g_hash_table_destroy(hk->hooked_regions);
        free(hk);
        return UC_ERR_NOMEM;
    }
    *hh = (uc_hook)hk;
    return UC_ERR_OK;
}

uc_err uca_hook_add_tcg_opcode(uc_engine *uc, uc_hook *hh,
                                void *callback, void *user_data,
                                uint64_t begin, uint64_t end,
                                int op, int op_flags)
{
    struct hook *hk = ucadapt_alloc_hook(callback, user_data, begin, end);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type     = UC_HOOK_TCG_OPCODE;
    hk->op       = op;
    hk->op_flags = op_flags;
    /* QEMU boundary: validate via arch TCG opcode table */
    if (uc->opcode_hook_invalidate &&
        !uc->opcode_hook_invalidate(hk->op, hk->op_flags)) {
        g_hash_table_destroy(hk->hooked_regions);
        free(hk);
        return UC_ERR_HOOK;
    }
    if (!ucadapt_hook_place_slot(uc, UC_HOOK_TCG_OPCODE_IDX, hk)) {
        g_hash_table_destroy(hk->hooked_regions);
        free(hk);
        return UC_ERR_NOMEM;
    }
    *hh = (uc_hook)hk;
    return UC_ERR_OK;
}

uc_err uca_hook_add_type(uc_engine *uc, uc_hook *hh, int type,
                         void *callback, void *user_data,
                         uint64_t begin, uint64_t end)
{
    int i = 0;
    struct hook *hk = ucadapt_alloc_hook(callback, user_data, begin, end);
    if (!hk)
        return UC_ERR_NOMEM;
    hk->type = type;

    /* Iterate bits of the type mask and register in every matching slot. */
    while ((type >> i) > 0) {
        if (((type >> i) & 1) && i < UC_HOOK_MAX) {
            if (!ucadapt_hook_place_slot(uc, (uc_hook_idx)i, hk)) {
                /* Roll back already-inserted entries. */
                for (int j = 0; j < i; j++) {
                    if (list_exists(&uc->unicorn.hook[j], hk)) {
                        list_remove(&uc->unicorn.hook[j], hk);
                        hk->refs--;
                        uc->unicorn.hooks_count[j]--;
                    }
                }
                g_hash_table_destroy(hk->hooked_regions);
                free(hk);
                return UC_ERR_NOMEM;
            }
        }
        i++;
    }

    if (hk->refs == 0) {
        /* type had no valid hook slots — free and return OK (original behaviour). */
        g_hash_table_destroy(hk->hooked_regions);
        free(hk);
    }

    *hh = (uc_hook)hk;
    return UC_ERR_OK;
}


/* =========================================================================
 * Virtual-address memory access — goes through arch MMU translation.
 *
 * These call uc_struct function pointers that perform a software TLB walk
 * (QEMU boundary) and then forward to the physical-address read/write path.
 * ========================================================================= */

uc_err uca_vmem_translate(uc_engine *uc, uint64_t address, uc_prot prot,
                           uint64_t *paddress)
{
    if (!(prot == UC_PROT_READ || prot == UC_PROT_WRITE ||
          prot == UC_PROT_EXEC))
        return UC_ERR_ARG;

    /* SPARC probe mode not supported — checked at call site for SPARC. */
    if (uc->arch == UC_ARCH_SPARC &&
        uc->cpu->cc->tlb_fill == uc->cpu->cc->tlb_fill_cpu)
        return UC_ERR_ARG;

    /* QEMU boundary: arch MMU virtual-to-physical translation */
    if (!uc->virtual_to_physical(uc, address, prot, paddress)) {
        switch (prot) {
        case UC_PROT_READ:  return UC_ERR_READ_PROT;
        case UC_PROT_WRITE: return UC_ERR_WRITE_PROT;
        case UC_PROT_EXEC:  return UC_ERR_FETCH_PROT;
        default:            return UC_ERR_ARG;
        }
    }
    return UC_ERR_OK;
}

uc_err uca_vmem_read(uc_engine *uc, uint64_t address, uc_prot prot,
                      void *buf, size_t size)
{
    size_t   count = 0, len;
    uint8_t *p = (uint8_t *)buf;
    uint64_t align, pagesize;

    if (size > INT_MAX)
        return UC_ERR_ARG;
    if (!(prot == UC_PROT_READ || prot == UC_PROT_WRITE ||
          prot == UC_PROT_EXEC))
        return UC_ERR_ARG;
    if (uc->arch == UC_ARCH_SPARC &&
        uc->cpu->cc->tlb_fill == uc->cpu->cc->tlb_fill_cpu)
        return UC_ERR_ARG;

    while (count < size) {
        align    = uc->target_page_align;
        pagesize = uc->target_page_size;
        len      = MIN(size - count,
                       (address & ~align) + pagesize - address);
        /* QEMU boundary: read via software MMU */
        if (!uc->read_mem_virtual(uc, address, prot, p, len))
            return UC_ERR_READ_PROT;
        p       += len;
        address += len;
        count   += len;
    }
    return UC_ERR_OK;
}

uc_err uca_vmem_write(uc_engine *uc, uint64_t address, uc_prot prot,
                       void *buf, size_t size)
{
    size_t   count = 0, len;
    uint8_t *p = (uint8_t *)buf;
    uint64_t align, pagesize, paddr;

    if (size > INT_MAX)
        return UC_ERR_ARG;
    if (!(prot == UC_PROT_READ || prot == UC_PROT_WRITE ||
          prot == UC_PROT_EXEC))
        return UC_ERR_ARG;
    if (uc->arch == UC_ARCH_SPARC &&
        uc->cpu->cc->tlb_fill == uc->cpu->cc->tlb_fill_cpu)
        return UC_ERR_ARG;

    while (count < size) {
        align    = uc->target_page_align;
        pagesize = uc->target_page_size;
        len      = MIN(size - count,
                       (address & ~align) + pagesize - address);
        uc_err err = uca_vmem_translate(uc, address, prot, &paddr);
        if (err != UC_ERR_OK)
            return UC_ERR_WRITE_PROT;
        if (uca_mem_write(uc, paddr, p, len) != UC_ERR_OK)
            return UC_ERR_WRITE_PROT;
        p       += len;
        address += len;
        count   += len;
    }
    return UC_ERR_OK;
}


/* =========================================================================
 * TCG translated-block and TLB control — thin QEMU boundary wrappers.
 *
 * These allow uc.c to forward UC_CTL_TB_* / UC_CTL_TLB_* control
 * operations without touching uc_struct function pointers directly.
 * ========================================================================= */

uc_err uca_tb_invalidate(uc_engine *uc, uint64_t addr, uint64_t len)
{
    /* QEMU boundary: flush translated blocks covering [addr, addr+len) */
    uc->uc_invalidate_tb(uc, addr, len);
    return UC_ERR_OK;
}

void uca_tb_flush(uc_engine *uc)
{
    /* QEMU boundary: discard entire translated-block cache */
    uc->tb_flush(uc);
}

void uca_tlb_flush(uc_engine *uc)
{
    /* QEMU boundary: flush the software TLB */
    uc->tcg_flush_tlb(uc);
}

uc_err uca_tlb_set_type(uc_engine *uc, int mode)
{
    /* QEMU boundary: switch TLB implementation variant */
    return uc->set_tlb(uc, mode);
}

uc_err uca_tb_request(uc_engine *uc, uint64_t addr, uc_tb *out_tb)
{
    /* QEMU boundary: JIT-compile one TB and return its descriptor */
    return uc->uc_gen_tb(uc, addr, out_tb);
}


/* =========================================================================
 * Context allocation and size query
 * ========================================================================= */

size_t uca_context_size(uc_engine *uc)
{
    /* QEMU boundary: arch-specific context size function pointer */
    if (!uc->context_size)
        return sizeof(uc_context) + uc->cpu_context_size;
    return sizeof(uc_context) + uc->context_size(uc);
}

uc_err uca_context_alloc(uc_engine *uc, uc_context **context)
{
    size_t sz = uca_context_size(uc);
    *context = g_malloc(sz);
    if (!*context)
        return UC_ERR_NOMEM;
    (*context)->context_size = sz - sizeof(uc_context);
    (*context)->arch         = uc->arch;
    (*context)->mode         = uc->mode;
    (*context)->fv           = NULL;
    return UC_ERR_OK;
}


/* =========================================================================
 * Memory region enumeration
 * ========================================================================= */

uc_err uca_mem_regions(uc_engine *uc, uc_mem_region **regions,
                        uint32_t *count)
{
    uint32_t n = uc->unicorn.mapped_block_count;
    *count = n;

    if (n == 0) {
        *regions = NULL;
        return UC_ERR_OK;
    }

    uc_mem_region *r = g_malloc0(n * sizeof(uc_mem_region));
    if (!r)
        return UC_ERR_NOMEM;

    for (uint32_t i = 0; i < n; i++) {
        /* QEMU boundary: read MemoryRegion address/size/permission fields */
        r[i].begin = uc->unicorn.mapped_blocks[i]->addr;
        r[i].end   = uc->unicorn.mapped_blocks[i]->end - 1;
        r[i].perms = uc->unicorn.mapped_blocks[i]->perms;
    }

    *regions = r;
    return UC_ERR_OK;
}


/* =========================================================================
 * Snapshots — wraps uc_struct CPU-state and QEMU memory FlatView functions
 *
 * A snapshot captures:
 *   1. CPU register state  — via uc->context_save (QEMU boundary)
 *   2. Emulated memory     — via uc->flatview_copy + CoW snapshot_level
 *                            (QEMU boundary)
 *
 * Restore is idempotent: the same snapshot can be restored multiple times.
 * ========================================================================= */

struct uca_snapshot {
    uc_context *ctx;
};

/* Restore the CoW memory state to the saved snapshot level.
 * Mirrors the static uc_restore_latest_snapshot() in uc.c. */
static uc_err ucadapt_restore_snapshot(uc_engine *uc)
{
    MemoryRegion *sub, *sub_next;

    /* QEMU boundary: remove subregions added after the snapshot was taken */
    QTAILQ_FOREACH_SAFE(sub, &uc->system_memory->subregions,
                        subregions_link, sub_next) {
        uc->memory_filter_subregions(sub, uc->unicorn.snapshot_level);
        if (sub->priority >= uc->unicorn.snapshot_level ||
            (!sub->terminates && QTAILQ_EMPTY(&sub->subregions)))
            /* QEMU boundary: delete subregion from QEMU memory graph */
            uc->memory_unmap(uc, sub);
    }

    /* QEMU boundary: re-map regions moved out during this snapshot level */
    for (size_t i = uc->unmapped_regions->len; i-- > 0;) {
        MemoryRegion *mr =
            g_array_index(uc->unmapped_regions, MemoryRegion *, i);
        MemoryRegion *initial =
            QTAILQ_FIRST(&mr->subregions) ? QTAILQ_FIRST(&mr->subregions) : mr;
        int level = (intptr_t)mr->container;
        mr->container = NULL;
        if (level < uc->unicorn.snapshot_level)
            break;
        if (ucadapt_overlaps(uc, mr->addr, (size_t)int128_get64(mr->size)))
            return UC_ERR_MAP;
        /* QEMU boundary: re-attach region into the address space */
        uc->memory_movein(uc, mr);
        uc->memory_filter_subregions(mr, uc->unicorn.snapshot_level);
        ucadapt_mem_track(uc, initial);
        g_array_remove_range(uc->unmapped_regions, (guint)i, 1);
    }

    uc->unicorn.snapshot_level--;
    return UC_ERR_OK;
}

uc_err uca_snapshot_take(uc_engine *uc, uca_snapshot **out)
{
    if (!out)
        return UC_ERR_ARG;
    if (uc->unicorn.snapshot_level == INT32_MAX)
        return UC_ERR_RESOURCE;

    uca_snapshot *s = calloc(1, sizeof(*s));
    if (!s)
        return UC_ERR_NOMEM;

    size_t cpu_sz = uc->context_size
                        ? uc->context_size(uc)
                        : (size_t)uc->cpu_context_size;

    s->ctx = calloc(1, sizeof(uc_context) + cpu_sz);
    if (!s->ctx) {
        free(s);
        return UC_ERR_NOMEM;
    }
    s->ctx->context_size = cpu_sz;
    s->ctx->arch         = uc->arch;
    s->ctx->mode         = uc->mode;

    /* Snapshot memory: copy the current FlatView (QEMU address-space map). */
    s->ctx->fv = g_malloc0(sizeof(FlatView));
    if (!s->ctx->fv) {
        free(s->ctx);
        free(s);
        return UC_ERR_NOMEM;
    }
    /* QEMU boundary: uc->flatview_copy snapshots the QEMU memory layout */
    if (!uc->flatview_copy(uc, s->ctx->fv,
                           uc->address_space_memory.current_map, false)) {
        g_free(s->ctx->fv);
        free(s->ctx);
        free(s);
        return UC_ERR_NOMEM;
    }

    /* Increment the CoW level so subsequent writes copy pages on write. */
    uc->unicorn.snapshot_level++;
    s->ctx->snapshot_level = uc->unicorn.snapshot_level;
    s->ctx->ramblock_freed = uc->ram_list.freed;
    s->ctx->last_block     = uc->ram_list.last_block;

    /* QEMU boundary: flush TCG TLB to pick up the new snapshot level */
    uc->tcg_flush_tlb(uc);

    /* Save CPU register state. */
    uc_err err;
    if (uc->context_save)
        /* QEMU boundary: arch-specific register serialisation */
        err = uc->context_save(uc, s->ctx);
    else
        /* QEMU boundary: raw copy of CPUArchState */
        err = (memcpy(s->ctx->data, uc->cpu->env_ptr, cpu_sz), UC_ERR_OK);

    if (err) {
        g_free(s->ctx->fv);
        free(s->ctx);
        free(s);
        return err;
    }

    *out = s;
    return UC_ERR_OK;
}

uc_err uca_snapshot_restore(uc_engine *uc, uca_snapshot *snap)
{
    if (!snap || !snap->ctx)
        return UC_ERR_ARG;

    uc_context *ctx = snap->ctx;

    /* Restore the QEMU memory layout to the saved FlatView. */
    uc->unicorn.snapshot_level = ctx->snapshot_level;
    /* QEMU boundary: apply saved FlatView (QEMU memory address-space map) */
    if (!uc->flatview_copy(uc, uc->address_space_memory.current_map,
                           ctx->fv, true))
        return UC_ERR_NOMEM;

    /* Roll back CoW pages written after the snapshot (decrements level). */
    uc_err err = ucadapt_restore_snapshot(uc);
    if (err)
        return err;

    /* Re-increment so the snapshot remains valid for future restores. */
    if (uc->unicorn.snapshot_level < INT32_MAX)
        uc->unicorn.snapshot_level++;

    uc->ram_list.freed      = ctx->ramblock_freed;
    uc->ram_list.last_block = ctx->last_block;
    /* QEMU boundary: flush TCG TLB after memory state is restored */
    uc->tcg_flush_tlb(uc);

    /* Restore CPU register state. */
    if (uc->context_restore)
        /* QEMU boundary: arch-specific register deserialisation */
        err = uc->context_restore(uc, ctx);
    else
        /* QEMU boundary: raw copy back into CPUArchState */
        err = (memcpy(uc->cpu->env_ptr, ctx->data, ctx->context_size),
               UC_ERR_OK);

    return err;
}

void uca_snapshot_free(uca_snapshot *snap)
{
    if (!snap)
        return;
    if (snap->ctx) {
        if (snap->ctx->fv) {
            free(snap->ctx->fv->ranges);
            g_free(snap->ctx->fv);
        }
        free(snap->ctx);
    }
    free(snap);
}


/* =========================================================================
 * Context save / restore — caller-allocated uc_context bridge
 *
 * These functions implement the same logic as uc_context_save/restore in
 * uc.c but route every QEMU boundary crossing through uc_struct function
 * pointers.  Behaviour is gated on uc->context_content flags exactly as
 * the original public functions.
 * ========================================================================= */

uc_err uca_context_save(uc_engine *uc, uc_context *context)
{
    uc_err ret = UC_ERR_OK;

    if (uc->context_content & UC_CTL_CONTEXT_MEMORY) {
        if (!context->fv) {
            context->fv = g_malloc0(sizeof(*context->fv));
        }
        if (!context->fv)
            return UC_ERR_NOMEM;
        /* QEMU boundary: snapshot the current address-space FlatView */
        if (!uc->flatview_copy(uc, context->fv,
                               uc->address_space_memory.current_map, false))
            return UC_ERR_NOMEM;
        /* Bump the CoW generation counter (inline equivalent of uc_snapshot). */
        if (uc->unicorn.snapshot_level == INT32_MAX)
            return UC_ERR_RESOURCE;
        uc->unicorn.snapshot_level++;
        context->ramblock_freed = uc->ram_list.freed;
        context->last_block     = uc->ram_list.last_block;
        /* QEMU boundary: flush TCG TLB so the new CoW level takes effect */
        uc->tcg_flush_tlb(uc);
    }

    context->snapshot_level = uc->unicorn.snapshot_level;

    if (uc->context_content & UC_CTL_CONTEXT_CPU) {
        if (!uc->context_save) {
            /* QEMU boundary: raw CPUArchState copy */
            memcpy(context->data, uc->cpu->env_ptr, context->context_size);
            return UC_ERR_OK;
        } else {
            /* QEMU boundary: arch-specific register serialisation */
            ret = uc->context_save(uc, context);
            return ret;
        }
    }
    return ret;
}

uc_err uca_context_restore(uc_engine *uc, uc_context *context)
{
    uc_err ret;

    if (uc->context_content & UC_CTL_CONTEXT_MEMORY) {
        uc->unicorn.snapshot_level = context->snapshot_level;
        /* QEMU boundary: restore the saved FlatView into the address space */
        if (!uc->flatview_copy(uc, uc->address_space_memory.current_map,
                               context->fv, true))
            return UC_ERR_NOMEM;
        /* Roll back any CoW pages written after the snapshot. */
        ret = ucadapt_restore_snapshot(uc);
        if (ret != UC_ERR_OK)
            return ret;
        /* Re-increment so the context remains usable for future restores. */
        if (uc->unicorn.snapshot_level == INT32_MAX)
            return UC_ERR_RESOURCE;
        uc->unicorn.snapshot_level++;
        uc->ram_list.freed      = context->ramblock_freed;
        uc->ram_list.last_block = context->last_block;
        /* QEMU boundary: flush TCG TLB after memory state is restored */
        uc->tcg_flush_tlb(uc);
    }

    if (uc->context_content & UC_CTL_CONTEXT_CPU) {
        if (!uc->context_restore) {
            /* QEMU boundary: raw CPUArchState restore */
            memcpy(uc->cpu->env_ptr, context->data, context->context_size);
            return UC_ERR_OK;
        } else {
            /* QEMU boundary: arch-specific register deserialisation */
            return uc->context_restore(uc, context);
        }
    }
    return UC_ERR_OK;
}


/* =========================================================================
 * Interrupt router — single UC_HOOK_INTR_IDX entry, dispatch by intno
 *
 * Installs exactly one hook node into uc->unicorn.hook[UC_HOOK_INTR_IDX].
 * The hook callback receives every interrupt and routes it to the handler
 * registered for its number.  The QEMU TCG arch interrupt helper fires the
 * UC_HOOK_INTR list when an interrupt/exception occurs.
 * ========================================================================= */

typedef struct uca_intr_entry {
    uint32_t           intno;
    uca_intr_handler_t handler;
    void              *user_data;
    struct uca_intr_entry *next;
} uca_intr_entry;

struct uca_intr_router {
    struct hook    *hk;      /* node live in uc->unicorn.hook[INTR_IDX] */
    uca_intr_entry *entries; /* linked list of per-number handlers */
};

static void ucadapt_intr_dispatch(uc_engine *uc, uint32_t intno,
                                  void *user_data)
{
    uca_intr_router *r = (uca_intr_router *)user_data;
    for (uca_intr_entry *e = r->entries; e; e = e->next)
        if (e->intno == intno) {
            e->handler(uc, intno, e->user_data);
            return;
        }
}

uc_err uca_intr_router_create(uc_engine *uc, uca_intr_router **out)
{
    if (!out)
        return UC_ERR_ARG;

    uca_intr_router *r = calloc(1, sizeof(*r));
    if (!r)
        return UC_ERR_NOMEM;

    r->hk = ucadapt_alloc_hook(ucadapt_intr_dispatch, r, 1, 0);
    if (!r->hk) {
        free(r);
        return UC_ERR_NOMEM;
    }
    r->hk->type = UC_HOOK_INTR;

    /* Insert directly into UnicornVM hook list — no public API involved */
    if (!list_append(&uc->unicorn.hook[UC_HOOK_INTR_IDX], r->hk)) {
        g_hash_table_destroy(r->hk->hooked_regions);
        free(r->hk);
        free(r);
        return UC_ERR_NOMEM;
    }
    r->hk->refs++;
    uc->unicorn.hooks_count[UC_HOOK_INTR_IDX]++;

    *out = r;
    return UC_ERR_OK;
}

uc_err uca_intr_register(uca_intr_router *router, uint32_t intno,
                         uca_intr_handler_t handler, void *user_data)
{
    if (!router || !handler)
        return UC_ERR_ARG;

    for (uca_intr_entry *e = router->entries; e; e = e->next)
        if (e->intno == intno) {
            e->handler   = handler;
            e->user_data = user_data;
            return UC_ERR_OK;
        }

    uca_intr_entry *e = malloc(sizeof(*e));
    if (!e)
        return UC_ERR_NOMEM;
    e->intno     = intno;
    e->handler   = handler;
    e->user_data = user_data;
    e->next      = router->entries;
    router->entries = e;
    return UC_ERR_OK;
}

void uca_intr_unregister(uca_intr_router *router, uint32_t intno)
{
    if (!router)
        return;
    uca_intr_entry **pp = &router->entries;
    while (*pp) {
        if ((*pp)->intno == intno) {
            uca_intr_entry *dead = *pp;
            *pp = dead->next;
            free(dead);
            return;
        }
        pp = &(*pp)->next;
    }
}

void uca_intr_router_free(uc_engine *uc, uca_intr_router *router)
{
    if (!router)
        return;

    /* Lazy-delete the hook from UnicornVM (cleaned up by uc_emu_start). */
    if (list_exists(&uc->unicorn.hook[UC_HOOK_INTR_IDX], router->hk)) {
        /* QEMU boundary: invalidate any TBs that were instrumented */
        g_hash_table_foreach(router->hk->hooked_regions,
                             ucadapt_invalidate_region, uc);
        g_hash_table_remove_all(router->hk->hooked_regions);
        router->hk->to_delete = true;
        uc->unicorn.hooks_count[UC_HOOK_INTR_IDX]--;
        list_append(&uc->unicorn.hooks_to_del, router->hk);
    }

    uca_intr_entry *e = router->entries;
    while (e) {
        uca_intr_entry *next = e->next;
        free(e);
        e = next;
    }
    free(router);
}


/* =========================================================================
 * Engine lifecycle — QEMU init, teardown
 * ========================================================================= */

static uc_err default_reg_read_stub(void *env, int mode, unsigned int regid,
                                    void *value, size_t *size)
{
    return UC_ERR_HANDLE;
}

static uc_err default_reg_write_stub(void *env, int mode, unsigned int regid,
                                     const void *value, size_t *size,
                                     int *setpc)
{
    return UC_ERR_HANDLE;
}

/* hook_delete is defined in uc.c and used by the list infrastructure.
 * Declare it here so the lifecycle functions can reference it. */
static void ucadapt_hook_delete(void *data)
{
    struct hook *h = (struct hook *)data;
    h->refs--;
    if (h->refs == 0) {
        g_hash_table_destroy(h->hooked_regions);
        free(h);
    }
}

static gint ucadapt_exits_cmp(gconstpointer a, gconstpointer b,
                               gpointer user_data)
{
    uint64_t lhs = *((uint64_t *)a);
    uint64_t rhs = *((uint64_t *)b);
    return (lhs < rhs) ? -1 : (lhs == rhs) ? 0 : 1;
}

uc_err uca_engine_alloc(uc_arch arch, uc_mode mode, uc_engine **out)
{
    struct uc_struct *uc = calloc(1, sizeof(*uc));
    if (!uc)
        return UC_ERR_NOMEM;

    /* QEMU boundary: phys_map_node_reserve() uses alloc_hint */
    uc->alloc_hint = 16;
    uc->errnum     = UC_ERR_OK;
    uc->arch       = arch;
    uc->mode       = mode;
    uc->reg_read   = default_reg_read_stub;
    uc->reg_write  = default_reg_write_stub;

    /* QEMU boundary: initialise QEMU RAM/address-space list heads */
    QLIST_INIT(&uc->ram_list.blocks);
    QTAILQ_INIT(&uc->memory_listeners);
    QTAILQ_INIT(&uc->address_spaces);

    uc->init_done  = false;
    uc->cpu_model  = INT_MAX; /* default CPU model */

    *out = uc;
    return UC_ERR_OK;
}

uc_err uca_engine_init(uc_engine *uc)
{
    if (uc->init_done)
        return UC_ERR_HANDLE;

    uc->unicorn.hooks_to_del.delete_fn = ucadapt_hook_delete;
    for (int i = 0; i < UC_HOOK_MAX; i++)
        uc->unicorn.hook[i].delete_fn = ucadapt_hook_delete;

    uc->ctl_exits = g_tree_new_full(ucadapt_exits_cmp, NULL, g_free, NULL);

    /* QEMU boundary: bring up the softmmu machine (CPUs, memory, TCG) */
    if (machine_initialize(uc))
        return UC_ERR_RESOURCE;

    /* QEMU boundary: select TLB implementation if not set by arch init */
    if (!uc->cpu->cc->tlb_fill)
        uc->set_tlb(uc, UC_TLB_CPU);

    /* QEMU boundary: init softfloat rounding modes */
    uc->softfloat_initialize();

    if (uc->reg_reset)
        uc->reg_reset(uc);

    uc->context_content  = UC_CTL_CONTEXT_CPU;
    uc->unmapped_regions = g_array_new(false, false, sizeof(MemoryRegion *));
    uc->init_done        = true;
    return UC_ERR_OK;
}

uc_err uca_engine_close(uc_engine *uc)
{
    int i;
    MemoryRegion *mr;

    if (!uc->init_done) {
        free(uc);
        return UC_ERR_OK;
    }

    /* QEMU boundary: flush all translated blocks before freeing TCG context */
    uc->tb_flush(uc);

    /* QEMU boundary: release TCG JIT buffers and internal state */
    if (uc->release)
        uc->release(uc->tcg_ctx);
    g_free(uc->tcg_ctx);

    /* QEMU boundary: free CPU object and its address-space array */
    g_free(uc->cpu->cpu_ases);
    g_free(uc->cpu->thread);
    qemu_vfree(uc->cpu);

    /* QEMU boundary: destroy FlatView cache (hash table) */
    g_hash_table_destroy(uc->flat_views);

    /* QEMU boundary: call destructor on each MemoryRegion */
    mr = &uc->io_mem_unassigned;
    mr->destructor(mr);
    mr = uc->system_io;
    mr->destructor(mr);
    mr = uc->system_memory;
    mr->destructor(mr);
    g_free(uc->system_memory);
    g_free(uc->system_io);
    for (size_t idx = 0; idx < uc->unmapped_regions->len; idx++) {
        mr = g_array_index(uc->unmapped_regions, MemoryRegion *, idx);
        mr->destructor(mr);
        g_free(mr);
    }
    g_array_free(uc->unmapped_regions, true);

    if (uc->qemu_thread_data)
        g_free(uc->qemu_thread_data);

    g_free(uc->init_target_page);
    g_free(uc->l1_map);

    if (uc->bounce.buffer)
        qemu_vfree(uc->bounce.buffer);

    /* Clean up all pending hook deletions, then free every hook list. */
    {
        struct list_item *cur;
        struct hook *hook;
        for (cur = uc->unicorn.hooks_to_del.head;
             cur != NULL && (hook = (struct hook *)cur->data);
             cur = cur->next) {
            for (i = 0; i < UC_HOOK_MAX; i++)
                list_remove(&uc->unicorn.hook[i], (void *)hook);
        }
        list_clear(&uc->unicorn.hooks_to_del);
    }
    for (i = 0; i < UC_HOOK_MAX; i++)
        list_clear(&uc->unicorn.hook[i]);

    free(uc->unicorn.mapped_blocks);
    g_tree_destroy(uc->ctl_exits);

    memset(uc, 0, sizeof(*uc));
    free(uc);
    return UC_ERR_OK;
}


/* =========================================================================
 * Register I/O — thin wrappers over uc_struct function pointers
 *
 * All CPU register access goes through uc->reg_read / uc->reg_write which
 * are arch-specific function pointers set during machine_initialize.
 * break_translation_loop is called after PC-changing writes so the TCG
 * engine picks up the new PC on the next translation.
 * ========================================================================= */

uc_err uca_reg_read(uc_engine *uc, int regid, void *value)
{
    size_t size = (size_t)-1;
    /* QEMU boundary: arch-specific register read */
    return uc->reg_read(uc->cpu->env_ptr, uc->mode, regid, value, &size);
}

uc_err uca_reg_write(uc_engine *uc, int regid, const void *value)
{
    int setpc = 0;
    size_t size = (size_t)-1;
    /* QEMU boundary: arch-specific register write */
    uc_err err = uc->reg_write(uc->cpu->env_ptr, uc->mode, regid, value,
                               &size, &setpc);
    if (err)
        return err;
    if (setpc) {
        uc->quit_request = true;
        uc->skip_sync_pc_on_exit = true;
        /* QEMU boundary: kick TCG out of the current translation block */
        break_translation_loop(uc);
    }
    return UC_ERR_OK;
}

uc_err uca_reg_read2(uc_engine *uc, int regid, void *value, size_t *size)
{
    /* QEMU boundary: arch-specific register read with size out-param */
    return uc->reg_read(uc->cpu->env_ptr, uc->mode, regid, value, size);
}

uc_err uca_reg_write2(uc_engine *uc, int regid, const void *value,
                      size_t *size)
{
    int setpc = 0;
    /* QEMU boundary: arch-specific register write with size out-param */
    uc_err err = uc->reg_write(uc->cpu->env_ptr, uc->mode, regid, value,
                               size, &setpc);
    if (err)
        return err;
    if (setpc) {
        uc->quit_request = true;
        /* QEMU boundary: kick TCG out of the current translation block */
        break_translation_loop(uc);
    }
    return UC_ERR_OK;
}

uc_err uca_reg_read_batch(uc_engine *uc, int const *regs, void **vals,
                          int count)
{
    reg_read_t reg_read = uc->reg_read;
    void *env  = uc->cpu->env_ptr;
    int mode   = uc->mode;
    for (int i = 0; i < count; i++) {
        size_t size = (size_t)-1;
        /* QEMU boundary: arch-specific register read */
        uc_err err = reg_read(env, mode, regs[i], vals[i], &size);
        if (err)
            return err;
    }
    return UC_ERR_OK;
}

uc_err uca_reg_write_batch(uc_engine *uc, int const *regs,
                           void *const *vals, int count)
{
    reg_write_t reg_write = uc->reg_write;
    void *env  = uc->cpu->env_ptr;
    int mode   = uc->mode;
    int setpc  = 0;
    for (int i = 0; i < count; i++) {
        size_t size = (size_t)-1;
        /* QEMU boundary: arch-specific register write */
        uc_err err = reg_write(env, mode, regs[i], vals[i], &size, &setpc);
        if (err)
            return err;
    }
    if (setpc) {
        uc->quit_request = true;
        /* QEMU boundary: kick TCG out of the current translation block */
        break_translation_loop(uc);
    }
    return UC_ERR_OK;
}

uc_err uca_reg_read_batch2(uc_engine *uc, int const *regs, void *const *vals,
                           size_t *sizes, int count)
{
    reg_read_t reg_read = uc->reg_read;
    void *env  = uc->cpu->env_ptr;
    int mode   = uc->mode;
    for (int i = 0; i < count; i++) {
        /* QEMU boundary: arch-specific register read with size out-param */
        uc_err err = reg_read(env, mode, regs[i], vals[i], sizes + i);
        if (err)
            return err;
    }
    return UC_ERR_OK;
}

uc_err uca_reg_write_batch2(uc_engine *uc, int const *regs,
                            const void *const *vals, size_t *sizes, int count)
{
    reg_write_t reg_write = uc->reg_write;
    void *env  = uc->cpu->env_ptr;
    int mode   = uc->mode;
    int setpc  = 0;
    for (int i = 0; i < count; i++) {
        /* QEMU boundary: arch-specific register write with size out-param */
        uc_err err = reg_write(env, mode, regs[i], vals[i], sizes + i, &setpc);
        if (err)
            return err;
    }
    if (setpc) {
        uc->quit_request = true;
        /* QEMU boundary: kick TCG out of the current translation block */
        break_translation_loop(uc);
    }
    return UC_ERR_OK;
}


/* =========================================================================
 * Emulation control — vm_start, timeout, instruction count
 * ========================================================================= */

#define UCADAPT_TIMEOUT_STEP 2  /* microseconds between timeout polls */

static void *ucadapt_timeout_fn(void *arg)
{
    struct uc_struct *uc = arg;
    int64_t t0 = get_clock();
    do {
        usleep(UCADAPT_TIMEOUT_STEP);
        if (uc->emulation_done)
            break;
    } while ((uint64_t)(get_clock() - t0) < uc->timeout);

    if (!uc->emulation_done) {
        uc->timed_out = true;
        /* QEMU boundary: inject a stop request into the running VM */
        uca_emu_stop(uc);
    }
    return NULL;
}

static void ucadapt_hook_count_cb(struct uc_struct *uc, uint64_t address,
                                   uint32_t size, void *user_data)
{
    uc->emu_counter++;
    if (uc->emu_counter > uc->emu_count)
        /* QEMU boundary: stop the running emulation */
        uca_emu_stop(uc);
}

uc_err uca_emu_start(uc_engine *uc, uint64_t begin, uint64_t until,
                     uint64_t timeout, size_t count)
{
    uc->emu_counter    = 0;
    uc->invalid_error  = UC_ERR_OK;
    uc->emulation_done = false;
    uc->size_recur_mem = 0;
    uc->timed_out      = false;
    uc->first_tb       = true;

    if (uc->nested_level >= UC_MAX_NESTED_LEVEL)
        return UC_ERR_RESOURCE;
    uc->nested_level++;

    /* Set the starting PC via the public register-write path so that
     * all arch-specific PC synchronisation logic runs normally. */
    uint32_t begin_pc32 = READ_DWORD(begin);
    switch (uc->arch) {
    default:
        break;
#ifdef UNICORN_HAS_M68K
    case UC_ARCH_M68K:
        uca_reg_write(uc, UC_M68K_REG_PC, &begin_pc32);
        break;
#endif
#ifdef UNICORN_HAS_X86
    case UC_ARCH_X86:
        switch (uc->mode) {
        default: break;
        case UC_MODE_16: {
            uint16_t ip, cs;
            uca_reg_read(uc, UC_X86_REG_CS, &cs);
            ip = (uint16_t)(begin - cs * 16);
            uca_reg_write(uc, UC_X86_REG_IP, &ip);
            break;
        }
        case UC_MODE_32:
            uca_reg_write(uc, UC_X86_REG_EIP, &begin_pc32);
            break;
        case UC_MODE_64:
            uca_reg_write(uc, UC_X86_REG_RIP, &begin);
            break;
        }
        break;
#endif
#ifdef UNICORN_HAS_ARM
    case UC_ARCH_ARM:
        uca_reg_write(uc, UC_ARM_REG_R15, &begin_pc32);
        break;
#endif
#ifdef UNICORN_HAS_ARM64
    case UC_ARCH_ARM64:
        uca_reg_write(uc, UC_ARM64_REG_PC, &begin);
        break;
#endif
#ifdef UNICORN_HAS_MIPS
    case UC_ARCH_MIPS:
        if (uc->mode & UC_MODE_MIPS64)
            uca_reg_write(uc, UC_MIPS_REG_PC, &begin);
        else
            uca_reg_write(uc, UC_MIPS_REG_PC, &begin_pc32);
        break;
#endif
#ifdef UNICORN_HAS_SPARC
    case UC_ARCH_SPARC:
        uca_reg_write(uc, UC_SPARC_REG_PC, &begin);
        break;
#endif
#ifdef UNICORN_HAS_PPC
    case UC_ARCH_PPC:
        if (uc->mode & UC_MODE_PPC64)
            uca_reg_write(uc, UC_PPC_REG_PC, &begin);
        else
            uca_reg_write(uc, UC_PPC_REG_PC, &begin_pc32);
        break;
#endif
#ifdef UNICORN_HAS_RISCV
    case UC_ARCH_RISCV:
        if (uc->mode & UC_MODE_RISCV64)
            uca_reg_write(uc, UC_RISCV_REG_PC, &begin);
        else
            uca_reg_write(uc, UC_RISCV_REG_PC, &begin_pc32);
        break;
#endif
#ifdef UNICORN_HAS_S390X
    case UC_ARCH_S390X:
        uca_reg_write(uc, UC_S390X_REG_PC, &begin);
        break;
#endif
#ifdef UNICORN_HAS_TRICORE
    case UC_ARCH_TRICORE:
        uca_reg_write(uc, UC_TRICORE_REG_PC, &begin_pc32);
        break;
#endif
    }

    uc->skip_sync_pc_on_exit = false;
    uc->stop_request         = false;
    uc->emu_count            = count;

    /* Remove instruction-count hook when not needed. */
    if (count == 0 && uc->unicorn.count_hook != 0) {
        uca_hook_del(uc, uc->unicorn.count_hook);
        uc->unicorn.count_hook = 0;
        /* QEMU boundary: flush TB cache so hook removal takes effect */
        uc->tb_flush(uc);
    }

    /* Install instruction-count hook when needed. */
    if (count > 0 && uc->unicorn.count_hook == 0) {
        uc->unicorn.hook_insert = 1;
        uc_err herr = uca_hook_add_type(
            uc, &uc->unicorn.count_hook, UC_HOOK_CODE,
            ucadapt_hook_count_cb, NULL, 1, 0);
        uc->unicorn.hook_insert = 0;
        if (herr != UC_ERR_OK) {
            uc->nested_level--;
            return herr;
        }
    }

    if (!uc->use_exits)
        uc->exits[uc->nested_level - 1] = until;

    if (timeout) {
        uc->timeout = timeout * 1000; /* microseconds → nanoseconds */
        /* QEMU boundary: create timeout watchdog thread */
        qemu_thread_create(uc, &uc->timer, "timeout",
                           ucadapt_timeout_fn, uc, QEMU_THREAD_JOINABLE);
    }

    /* QEMU boundary: enter the TCG main loop */
    uc->vm_start(uc);

    uc->nested_level--;

    if (uc->nested_level == 0) {
        uc->emulation_done = true;

        /* Flush deferred hook deletions at outermost level only. */
        {
            struct list_item *cur;
            struct hook *hook;
            int i;
            for (cur = uc->unicorn.hooks_to_del.head;
                 cur != NULL && (hook = (struct hook *)cur->data);
                 cur = cur->next) {
                for (i = 0; i < UC_HOOK_MAX; i++)
                    if (list_remove(&uc->unicorn.hook[i], (void *)hook))
                        break;
            }
            list_clear(&uc->unicorn.hooks_to_del);
        }
    }

    if (timeout)
        /* QEMU boundary: join the timeout watchdog thread */
        qemu_thread_join(&uc->timer);

    uc_err err = uc->invalid_error;
    uc->invalid_error = 0;
    return err;
}

uc_err uca_emu_stop(uc_engine *uc)
{
    uc->stop_request = true;
    /* QEMU boundary: break out of the TCG translation loop immediately */
    return break_translation_loop(uc);
}


/* =========================================================================
 * Query
 * ========================================================================= */

uc_err uca_query(uc_engine *uc, uc_query_type type, size_t *result)
{
    switch (type) {
    default:
        return UC_ERR_ARG;

    case UC_QUERY_PAGE_SIZE:
        *result = uc->target_page_size;
        break;

    case UC_QUERY_ARCH:
        *result = uc->arch;
        break;

    case UC_QUERY_MODE:
#ifdef UNICORN_HAS_ARM
        if (uc->arch == UC_ARCH_ARM)
            /* QEMU boundary: ARM Thumb/ARM mode query via arch backend */
            return uc->query(uc, type, result);
#endif
        *result = uc->mode;
        break;

    case UC_QUERY_TIMEOUT:
        *result = uc->timed_out;
        break;
    }
    return UC_ERR_OK;
}
