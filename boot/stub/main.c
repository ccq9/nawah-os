/* boot/stub — pre-ExitBootServices stage of the single-image kernel (ADR-0001).
 * Responsibilities (docs/contracts/boot.md): validate the system table, obtain a
 * fresh memory map, call ExitBootServices with its key (one retry with a fresh
 * map on EFI_INVALID_PARAMETER), then hand boot_info to kernel_main. On failure:
 * diagnostic line, lab exit code 0x30, halt. No reboot loop.
 * Build with -DNAWAH_INJECT_EBS_FAIL=1 for TST-M1-NEG (stale key injection). */
#include "../common/efi.h"
#include "../common/serial.h"
#include "../common/bootinfo.h"

#ifndef BUILD_ID
#error "BUILD_ID must be defined by the build"
#endif
#define STR2(x) #x
#define STR(x) STR2(x)
#define BID STR(BUILD_ID)
#define EFI_SYSTEM_TABLE_SIGNATURE 0x5453595320494249ULL
#define LAB_EXIT_FAIL 0x30 /* QEMU exit 97 */

static __attribute__((noreturn)) void fail(const char *code, EFI_STATUS st) {
    serial_puts("OSX|" BID "|boot|error|code="); serial_puts(code);
    serial_puts("|status="); serial_puthex(st); serial_puts("\n");
    serial_puts("OSX|" BID "|boot|halt|reboot=0\n");
    qemu_exit(LAB_EXIT_FAIL);
}

static void copy_build_id(char *dst) {
    const char *s = BID; UINTN i = 0;
    for (; i < NAWAH_BUILD_ID_LEN - 1 && s[i]; i++) dst[i] = s[i];
    dst[i] = 0;
}

EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *st) {
    serial_init();
    serial_puts("OSX|" BID "|boot|start|arch=x86_64|boot=uefi|stage=pre_ebs\n");
    if (!st || st->Hdr.Signature != EFI_SYSTEM_TABLE_SIGNATURE || !st->BootServices)
        fail("BOOT_E_BAD_TABLE", EFI_INVALID_PARAMETER);
    EFI_BOOT_SERVICES *bs = st->BootServices;

    struct nawah_boot_info *bi = 0;
    EFI_STATUS s = bs->AllocatePool(EfiLoaderData, sizeof *bi, (VOID **)&bi);
    if (EFI_ERROR(s) || !bi) fail("BOOT_E_ALLOC", s);
    for (UINTN i = 0; i < sizeof *bi; i++) ((UINT8 *)bi)[i] = 0;
    bi->magic = NAWAH_BOOT_MAGIC; bi->version = NAWAH_BOOT_VERSION; bi->size = sizeof *bi;
    copy_build_id(bi->build_id);
    bi->runtime_services = st->RuntimeServices;

    /* Memory map: probe size, allocate with slack (the allocation itself may add descriptors). */
    UINTN map_size = 0, map_key = 0, desc_size = 0; UINT32 desc_ver = 0;
    s = bs->GetMemoryMap(&map_size, 0, &map_key, &desc_size, &desc_ver);
    if (s != EFI_BUFFER_TOO_SMALL) fail("BOOT_E_MAP_PROBE", s);
    map_size += 2 * desc_size;
    if (map_size > NAWAH_MAX_MEMMAP_BYTES) fail("BOOT_E_MAP_TOO_LARGE", map_size);
    EFI_MEMORY_DESCRIPTOR *map = 0;
    s = bs->AllocatePool(EfiLoaderData, map_size, (VOID **)&map);
    if (EFI_ERROR(s) || !map) fail("BOOT_E_ALLOC", s);

    UINT32 attempts = 0;
    for (;;) {
        UINTN sz = map_size;
        s = bs->GetMemoryMap(&sz, map, &map_key, &desc_size, &desc_ver);
        if (EFI_ERROR(s)) fail("BOOT_E_MAP_GET", s);
        serial_puts("OSX|" BID "|boot|memmap|bytes="); serial_putdec(sz);
        serial_puts("|desc_size="); serial_putdec(desc_size);
        serial_puts("|key="); serial_puthex(map_key); serial_puts("\n");
        UINTN key = map_key;
#ifdef NAWAH_INJECT_EBS_FAIL
        key ^= 0x1; /* deliberately stale key: firmware must reject it */
#endif
        attempts++;
        s = bs->ExitBootServices(ImageHandle, key);
        if (!EFI_ERROR(s)) {
            bi->memmap = (const struct nawah_mem_desc *)map; bi->memmap_bytes = sz;
            bi->descriptor_size = desc_size; bi->descriptor_version = desc_ver;
            bi->map_key = key; bi->ebs_attempts = attempts;
            break;
        }
        if (s == EFI_INVALID_PARAMETER && attempts < 2) {
            serial_puts("OSX|" BID "|boot|ebs|retry=1|status="); serial_puthex(s); serial_puts("\n");
            continue;
        }
        fail("BOOT_E_EBS_FAILED", s);
    }
    /* From here on, `bs` and `st` must not be used. The kernel never sees them. */
    bs = 0; st = 0;
    serial_puts("OSX|" BID "|boot|ebs|ok=1|attempts="); serial_putdec(attempts); serial_puts("\n");
    kernel_main(bi);
}
