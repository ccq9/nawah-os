/* E0 — decisive experiment (prompt 3.2, section 5). Proves only that the
 * toolchain produces a UEFI PE image that OVMF loads and runs on QEMU, that the
 * serial channel works, and that the exit-code path works. It is NOT the M1
 * kernel: it never calls ExitBootServices. */
#include "../common/efi.h"
#include "../common/serial.h"

#ifndef BUILD_ID
#error "BUILD_ID must be defined by the build"
#endif
#define STR2(x) #x
#define STR(x) STR2(x)

static CHAR16 hello16[] = u"nawah-os E0: UEFI application running\r\n";

EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    (void)ImageHandle;
    serial_init();
    serial_puts("OSX|" STR(BUILD_ID) "|e0|start|arch=x86_64|boot=uefi\n");
    if (SystemTable && SystemTable->ConOut) {
        SystemTable->ConOut->OutputString(SystemTable->ConOut, hello16);
        serial_puts("OSX|" STR(BUILD_ID) "|e0|conout|ok=1\n");
    } else {
        serial_puts("OSX|" STR(BUILD_ID) "|e0|conout|ok=0\n");
        qemu_exit(0x20); /* exit 65 */
    }
    serial_puts("OSX|" STR(BUILD_ID) "|e0|firmware|rev=");
    serial_puthex(SystemTable->Hdr.Revision);
    serial_puts("\n");
    serial_puts("OSX|" STR(BUILD_ID) "|e0|done|exit=0x10\n");
    qemu_exit(0x10); /* QEMU exit code 33 */
    return EFI_SUCCESS;
}
