/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::arch::x86_64::__cpuid;

const LEAF_FEATURES: u32 = 0x0000_0001;
const LEAF_EXTENDED_MAX: u32 = 0x8000_0000;
const LEAF_EXTENDED_FEATURES: u32 = 0x8000_0001;

const SSE3: u32 = 1 << 0;
const SSSE3: u32 = 1 << 9;
const CMPXCHG16B: u32 = 1 << 13;
const SSE4_1: u32 = 1 << 19;
const SSE4_2: u32 = 1 << 20;
const POPCNT: u32 = 1 << 23;
const LAHF_SAHF: u32 = 1 << 0;

const FEATURES_X86_64_V2: u32 = SSE3 | SSSE3 | CMPXCHG16B | SSE4_1 | SSE4_2 | POPCNT;
const EXTENDED_FEATURES_X86_64_V2: u32 = LAHF_SAHF;

const UNSUPPORTED_CPU: &[u8] = b"This build of Stalwart requires an x86-64-v2 compatible CPU (SSE3, SSSE3, SSE4.1, SSE4.2, POPCNT, CMPXCHG16B and LAHF/SAHF). If Stalwart runs in a virtual machine, set its CPU type to 'host' or 'x86-64-v2'.\n";
const EXIT_UNSUPPORTED_CPU: i32 = 1;

#[used]
#[unsafe(link_section = ".init_array.00001")]
static ASSERT_X86_64_V2: extern "C" fn() = assert_x86_64_v2;

extern "C" fn assert_x86_64_v2() {
    let features = __cpuid(LEAF_FEATURES).ecx;
    let extended_features = if __cpuid(LEAF_EXTENDED_MAX).eax >= LEAF_EXTENDED_FEATURES {
        __cpuid(LEAF_EXTENDED_FEATURES).ecx
    } else {
        0
    };

    if features & FEATURES_X86_64_V2 != FEATURES_X86_64_V2
        || extended_features & EXTENDED_FEATURES_X86_64_V2 != EXTENDED_FEATURES_X86_64_V2
    {
        unsafe {
            libc::write(
                libc::STDERR_FILENO,
                UNSUPPORTED_CPU.as_ptr().cast(),
                UNSUPPORTED_CPU.len(),
            );
            libc::_exit(EXIT_UNSUPPORTED_CPU);
        }
    }
}
