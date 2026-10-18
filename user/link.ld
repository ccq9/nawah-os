/* nawah-os application layout (WP-17, ADR-0012): static ET_EXEC at APP_BASE; the loader maps
   each PT_LOAD page by page with W^X. Sections of different permissions start on new pages
   (and the linker is run with -z separate-loadable-segments). */
ENTRY(_start)
SECTIONS
{
  /* ELF and program headers live in the first page of the window (a read-only PT_LOAD);
     .text starts on the next page. */
  . = 0x8010000000 + SIZEOF_HEADERS;
  . = ALIGN(4096);
  .text : { *(.text .text.*) }
  . = ALIGN(4096);
  .rodata : { *(.rodata .rodata.*) *(.data.rel.ro .data.rel.ro.*) }
  .eh_frame_hdr : { *(.eh_frame_hdr) }
  .eh_frame : { *(.eh_frame) }
  . = ALIGN(4096);
  .data : { *(.data .data.*) *(.got .got.plt) }
  .bss : { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.note.*) *(.comment) }
}
