//! Fuzz the FPE round-trip property: decrypt(encrypt(x)) == x.
//!
//! This is the property unit test in `mapping/fpe.rs`, lifted to a
//! fuzzer.  Any input that breaks it would be a soundness bug in the
//! Fisher-Yates path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use babbleon::mapping::fpe;

fuzz_target!(|data: &[u8]| {
    // Minimum: 8 bytes for the seed proper, 1 byte for n_log2, 8 for
    // epoch, 4 for x.  Reject tiny inputs cheaply.
    if data.len() < 32 {
        return;
    }
    let seed = &data[..16];
    let n_log2 = (data[16] & 0b1111).max(1);   // n in [2, 65536]
    let n = 1usize << n_log2;

    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&data[17..25]);
    let epoch = u64::from_le_bytes(epoch_bytes);

    let mut x_bytes = [0u8; 4];
    x_bytes.copy_from_slice(&data[25..29]);
    let x = u32::from_le_bytes(x_bytes) as usize % n;

    let y = match fpe::encrypt(seed, epoch, n, x) {
        Some(y) => y,
        None => return,
    };
    assert!(y < n, "encrypt produced out-of-range output: y={y} n={n}");
    let back = fpe::decrypt(seed, epoch, n, y).expect("decrypt of in-range output");
    assert_eq!(back, x, "FPE round-trip broken: x={x} -> y={y} -> {back}");
});
