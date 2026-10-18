//! Applications embedded in the kernel image (WP-17): ELF files built from user/apps by
//! tools/project.py and handed to kernel/build.rs through `NAWAH_APPS_DIR`. Empty when the
//! kernel is built without them (host checks); the boot self-check then reports them missing.

include!(concat!(env!("OUT_DIR"), "/apps.rs"));
