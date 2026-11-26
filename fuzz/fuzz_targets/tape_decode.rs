#![no_main]
#![forbid(unsafe_code)]

use dtp_codec::TapeArchive;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    // Rejected inputs are expected. A panic or sanitizer finding fails the run.
    let _ = TapeArchive::decode(bytes);
});
