/* COM1 (16550, I/O port 0x3F8) diagnostic channel. Works before and after
 * ExitBootServices because it touches hardware directly, not firmware.
 * ASCII only (prompt 3.2, section 5). isa-debug-exit at port 0xF4 (QEMU):
 * QEMU exits with ((value << 1) | 1). */
#ifndef NAWAH_SERIAL_H
#define NAWAH_SERIAL_H
#include "types.h"

static inline void outb(UINT16 port, UINT8 v) { __asm__ volatile("outb %0, %1" : : "a"(v), "Nd"(port)); }
static inline void outl(UINT16 port, UINT32 v) { __asm__ volatile("outl %0, %1" : : "a"(v), "Nd"(port)); }
static inline UINT8 inb(UINT16 port) { UINT8 v; __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(port)); return v; }

#define COM1 0x3F8
#define QEMU_DEBUG_EXIT_PORT 0xF4

static inline void serial_init(void) {
    outb(COM1 + 1, 0x00);  /* disable interrupts */
    outb(COM1 + 3, 0x80);  /* DLAB on */
    outb(COM1 + 0, 0x01);  /* divisor 1 = 115200 */
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);  /* 8N1, DLAB off */
    outb(COM1 + 2, 0xC7);  /* FIFO on, clear */
    outb(COM1 + 4, 0x0B);  /* DTR, RTS, OUT2 */
}
static inline void serial_putc(char c) {
    while ((inb(COM1 + 5) & 0x20) == 0) { }
    outb(COM1, (UINT8)c);
}
static inline void serial_puts(const char *s) { while (*s) serial_putc(*s++); }
static inline void serial_puthex(UINT64 v) {
    static const char d[] = "0123456789abcdef";
    serial_puts("0x");
    for (int i = 60; i >= 0; i -= 4) serial_putc(d[(v >> i) & 0xF]);
}
static inline void serial_putdec(UINT64 v) {
    char buf[21]; int i = 20; buf[i] = 0;
    if (v == 0) { serial_putc('0'); return; }
    while (v) { buf[--i] = (char)('0' + v % 10); v /= 10; }
    serial_puts(buf + i);
}
/* Never returns under QEMU with isa-debug-exit; halts forever otherwise. */
static inline __attribute__((noreturn)) void qemu_exit(UINT32 code) {
    outl(QEMU_DEBUG_EXIT_PORT, code);
    for (;;) __asm__ volatile("cli; hlt");
}
#endif
