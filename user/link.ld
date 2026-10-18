/* nawah-os application layout (WP-17, ADR-0012): static ET_EXEC at APP_BASE; the loader maps
   each PT_LOAD page by page with W^X. Sections of different permissions start on new pages
   (and the linker is run with -z separate-loadable-segments). The large code model names its
   sections .ltext/.lrodata/.ldata/.lbss (CI run 39107332146: unmatched, they landed as orphans
   in the header page), so both spellings are listed. */
ENTRY(_start)
SECTIONS
{
  /* ELF and program headers live in the first page of the window (a read-only PT_LOAD);
     .text starts on the next page. */
  . = 0x8010000000 + SIZEOF_HEADERS;
  . = ALIGN(4096);
  .text : { *(.text .text.* .ltext .ltext.*) }
  . = ALIGN(4096);
  .rodata : { *(.rodata .rodata.* .lrodata .lrodata.*) *(.data.rel.ro .data.rel.ro.*) }
  .eh_frame_hdr : { *(.eh_frame_hdr) }
  .eh_frame : { *(.eh_frame) }
  . = ALIGN(4096);
  .data : { *(.data .data.* .ldata .ldata.*) *(.got .got.plt) }
  .bss : { *(.bss .bss.* .lbss .lbss.*) *(COMMON) }
  /DISCARD/ : { *(.note.*) *(.comment) }
}
