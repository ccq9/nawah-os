/* kernel/ — post-ExitBootServices stage. This translation unit must never
 * include efi.h, name a firmware function table, or receive the system table
 * (enforced statically by TST-M1-NOBS). It receives boot_info only. */
#include "../boot/common/bootinfo.h"
#include "../boot/common/serial.h"

#define LAB_EXIT_OK 0x10 /* QEMU exit 33 */
#define MEM_CONVENTIONAL 7  /* EfiConventionalMemory, UEFI 2.11 table 7-5 */

static __attribute__((noreturn)) void kpanic(const char *code) {
    serial_puts("OSX|?|kernel|panic|code="); serial_puts(code); serial_puts("\n");
    for (;;) __asm__ volatile("cli; hlt");
}

void kernel_main(const struct nawah_boot_info *bi) {
    if (!bi || bi->magic != NAWAH_BOOT_MAGIC) kpanic("K_E_BAD_BOOTINFO");
    if (bi->version != NAWAH_BOOT_VERSION || bi->size != sizeof *bi) kpanic("K_E_BOOTINFO_VERSION");
    if (!bi->memmap || bi->descriptor_size < sizeof(struct nawah_mem_desc)) kpanic("K_E_BAD_MEMMAP");

    UINTN n = bi->memmap_bytes / bi->descriptor_size, conventional_pages = 0;
    const UINT8 *p = (const UINT8 *)bi->memmap;
    for (UINTN i = 0; i < n; i++, p += bi->descriptor_size) {
        const struct nawah_mem_desc *d = (const struct nawah_mem_desc *)p;
        if (d->type == MEM_CONVENTIONAL) conventional_pages += d->pages;
    }
    serial_puts("OSX|"); serial_puts(bi->build_id); serial_puts("|kernel|post_ebs|map_key=");
    serial_puthex(bi->map_key); serial_puts("|descriptors="); serial_putdec(n);
    serial_puts("|conventional_pages="); serial_putdec(conventional_pages);
    serial_puts("|ebs_attempts="); serial_putdec(bi->ebs_attempts); serial_puts("\n");
    serial_puts("OSX|"); serial_puts(bi->build_id); serial_puts("|kernel|m1_done|exit=0x10\n");
    qemu_exit(LAB_EXIT_OK); /* lab only; a real target would continue to M2 init */
}
