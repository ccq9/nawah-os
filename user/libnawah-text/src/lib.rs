//! nawah-text — the text layer (WP-35, ADR-0019 §6): the Unicode Bidirectional Algorithm,
//! Arabic shaping, an OpenType reader and a scanline rasteriser, all `no_std`, allocation
//! free and `unsafe`-free. The library works on caller-provided buffers; the data it needs
//! (Unicode tables) is generated from the Unicode Character Database by
//! tools/unicode_tables.py.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod bidi;
pub mod font;
pub mod layout;
pub mod raster;
pub mod shape;
#[rustfmt::skip]
pub mod tables;
