

## crash type

Global-buffer-overflow

## project & version

https://gitlab.gnome.org/GNOME/libsoup  
test version: 3.0.0  
affected version: version <= 3.6.5(latest)

## crash position

in soup_header_name_to_string /libsoup/libsoup/soup-header-names.c:697
```
const char *soup_header_name_to_string (SoupHeaderName name)
{
        if (name == SOUP_HEADER_UNKNOWN)
                return NULL;

        return soup_headr_name_strings[name]; //crash here
}
```


## PoC
```
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "soup-header-names.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Need at least one byte for null termination
    SoupHeaderName name = (SoupHeaderName)data[0];
    const char *result = soup_header_name_to_string(name);
    return 0;
}

```

## crash description

The `soup_header_name_to_string` function does not validate the `name` parameter passed in, and directly accesses `soup_headr_name_strings[name]`. When `name` exceeds the index range of `soup_headr_name_string`, it will cause an out-of-bounds access.

## Crash log
```
+----------------------------------------Release Build Stacktrace----------------------------------------+
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 229309669
INFO: Loaded 1 modules   (64 inline 8-bit counters): 64 [0xfcdfa0, 0xfcdfe0),
INFO: Loaded 1 PC tables (64 PCs): 64 [0xf45c30,0xf46030),
INFO: -fork=2: fuzzing in separate process(s)
INFO: -fork=2: 0 seed inputs, starting to fuzz in /fuzz_set/workspace/bot_tmpdir/libFuzzerTemp.FuzzWithFork19.dir
#34: cov: 0 ft: 0 corp: 0 exec/s 0 oom/timeout/crash: 0/0/0 time: 0s job: 1 dft_time: 0
INFO: log from the inner process:
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 229338752
INFO: Loaded 1 modules   (64 inline 8-bit counters): 64 [0xfcdfa0, 0xfcdfe0),
INFO: Loaded 1 PC tables (64 PCs): 64 [0xf45c30,0xf46030),
INFO:        0 files found in /fuzz_set/workspace/bot_tmpdir/libFuzzerTemp.FuzzWithFork19.dir/C1
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
Created link file 'fuzzer_stats'
#2	INITED cov: 4 ft: 4 corp: 1/1b exec/s: 0 rss: 31Mb
=================================================================
==27==ERROR: AddressSanitizer: global-buffer-overflow on address 0x0000007853a0 at pc 0x00000057d458 bp 0x7fff8eaa7150 sp 0x7fff8eaa7148
READ of size 8 at 0x0000007853a0 thread T0
SCARINESS: 33 (8-byte-read-global-buffer-overflow-far-from-bounds)
    #0 0x57d457 in soup_header_name_to_string /src/libsoup-3-0-0/libsoup/soup-header-names.c:697:16
    #1 0x57bf32 in LLVMFuzzerTestOneInput /src/fuzzer.c:12:26
    #2 0x44fea3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #3 0x44f68a in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:514:3
    #4 0x450d59 in fuzzer::Fuzzer::MutateAndTestOne() /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:757:19
    #5 0x451a25 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:895:5
    #6 0x435ff1 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:1112:6
    #7 0x46a242 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #8 0x7fef29fe7082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/libc-start.c:308:16
    #9 0x4211fd in _start

0x0000007853a0 is located 13 bytes to the right of global variable 'lookup' defined in './libsoup/soup-header-names.c:607:26' (0x7850e0) of size 691
SUMMARY: AddressSanitizer: global-buffer-overflow (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57d457)
Shadow bytes around the buggy address:
  0x0000800e8a20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800e8a30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800e8a40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800e8a50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800e8a60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0000800e8a70: 00 00 03 f9[f9]f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x0000800e8a80: f9 f9 f9 f9 f9 f9 f9 f9 00 00 00 00 00 00 00 00
  0x0000800e8a90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800e8aa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800e8ab0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800e8ac0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==27==ABORTING
MS: 2 InsertByte-ChangeBinInt-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
0xc4,0xa,
\304\012
artifact_prefix='/fuzz_set/workspace/bot/inputs/fuzzer-testcases/'; Test unit written to /fuzz_set/workspace/bot/inputs/fuzzer-testcases/crash-f89b68b42cc6095aa911ec41ddfa578f4c3e5765
Base64: xAo=
stat::number_of_executed_units: 34
stat::average_exec_per_sec:     0
stat::new_units_added:          0
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              32
INFO: exiting: 77 time: 0s


+----------------------------------------Release Build Unsymbolized Stacktrace (diff)----------------------------------------+

READ of size 8 at 0x0000007853a0 thread T0
SCARINESS: 33 (8-byte-read-global-buffer-overflow-far-from-bounds)
    #0 0x57d457  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57d457)
    #1 0x57bf32  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57bf32)
    #2 0x44fea3  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44fea3)
    #3 0x44f68a  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44f68a)
    #4 0x450d59  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x450d59)
    #5 0x451a25  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451a25)
    #6 0x435ff1  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x435ff1)
    #7 0x46a242  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x46a242)
    #8 0x7fef29fe7082  (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #9 0x4211fd  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x4211fd)

```

## build command
```
#!/bin/bash
find . -name "*.c" -exec $CC $CFLAGS -I./src -c {} \;
find . -name "*.o" -exec cp {} . \;

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o


$CC $CFLAGS $LIB_FUZZING_ENGINE $SRC/fuzzer.c -Wl,--whole-archive $SRC/libsoup-3-0-0/libfuzz.a -Wl,--allow-multiple-definition -I$SRC/libsoup-3-0-0/fuzzing -I$SRC/libsoup-3-0-0/libsoup -I$SRC/libsoup-3-0-0/libsoup/auth -I$SRC/libsoup-3-0-0/libsoup/cookies -I$SRC/libsoup-3-0-0/libsoup/hsts -I$SRC/libsoup-3-0-0/libsoup/http1 -I$SRC/libsoup-3-0-0/libsoup/cache -I$SRC/libsoup-3-0-0/tests/pkcs11 -I$SRC/libsoup-3-0-0/libsoup/include -I$SRC/libsoup-3-0-0/libsoup/websocket -I$SRC/libsoup-3-0-0/tests -I$SRC/libsoup-3-0-0/libsoup/content-sniffer -I$SRC/libsoup-3-0-0/libsoup/server -I$SRC/libsoup-3-0-0/libsoup/http2 -I$SRC/libsoup-3-0-0/libsoup/content-decoder  -o $OUT/fuzzer
```

## Fuzz instruction
```
[Environment] ASAN_OPTIONS=alloc_dealloc_mismatch=0:allocator_may_return_null=1:allocator_release_to_os_interval_ms=500:allow_user_segv_handler=0:check_malloc_usable_size=0:detect_leaks=1:detect_odr_violation=0:detect_stack_use_after_return=1:exitcode=77:fast_unwind_on_fatal=0:handle_abort=2:handle_segv=2:handle_sigbus=2:handle_sigfpe=2:handle_sigill=2:max_uar_stack_size_log=16:print_scariness=1:print_summary=1:print_suppressions=0:quarantine_size_mb=64:strict_memcmp=1:symbolize=0:use_sigaltstack=1
```

```
["/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer","-timeout=25","-rss_limit_mb=2560","-artifact_prefix=/fuzz_set/workspace/bot/inputs/fuzzer-testcases/","-max_total_time=5700","-print_final_stats=1","/fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/new","/fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/mutations","/fuzz_set/workspace/bot/inputs/data-bundles/fuzzer"]
```

