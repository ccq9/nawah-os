//! Device drivers (WP-18). Each driver owns its device behind a lock and exposes a small,
//! synchronous API to the layer above (block/).

pub mod virtio_blk;
