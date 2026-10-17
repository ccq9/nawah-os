/* boot_info — the only thing handed from the pre-ExitBootServices stage (boot/)
 * to the kernel (kernel/). Contract: docs/contracts/boot.md, version 1.
 * Deliberately contains no firmware function tables: the kernel must not be
 * able to reach Boot Services through it. */
#ifndef NAWAH_BOOTINFO_H
#define NAWAH_BOOTINFO_H
#include "types.h"

#define NAWAH_BOOT_MAGIC   0x4F46494E54424E57ULL /* "WNBTNIFO" little-endian */
#define NAWAH_BOOT_VERSION 1
#define NAWAH_BUILD_ID_LEN 32
#define NAWAH_MAX_MEMMAP_BYTES (64 * 1024)

/* Mirrors EFI_MEMORY_DESCRIPTOR layout (UEFI 2.11 §7.2.3) without naming firmware types. */
struct nawah_mem_desc {
    UINT32 type; UINT32 pad; UINT64 phys_start; UINT64 virt_start; UINT64 pages; UINT64 attribute;
};

struct nawah_framebuffer { UINT64 base; UINT32 width, height, pitch_px, pixel_format; BOOLEAN present; };

struct nawah_boot_info {
    UINT64 magic;
    UINT32 version;
    UINT32 size;                       /* sizeof(struct nawah_boot_info) */
    char   build_id[NAWAH_BUILD_ID_LEN];
    const struct nawah_mem_desc *memmap;  /* firmware-owned buffer handed to the kernel after EBS */
    UINTN  memmap_bytes;
    UINTN  descriptor_size;
    UINT32 descriptor_version;
    UINTN  map_key;                    /* the key accepted by ExitBootServices */
    UINT32 ebs_attempts;               /* 1 or 2 */
    struct nawah_framebuffer fb;       /* not populated in M1 (present = 0) */
    UINT64 rsdp;                       /* 0 in M1 */
    VOID  *runtime_services;           /* EFI_RUNTIME_SERVICES*, opaque to the kernel in M1 */
};

/* Implemented in kernel/main.c. Never returns. */
void kernel_main(const struct nawah_boot_info *bi) __attribute__((noreturn));
#endif
