

## crash type

Heap-buffer-overflow

## project & version

https://github.com/nanopb/nanopb  
0.4.9

## crash position

in get_allocation_size /nanopb/tests/common/malloc_wrappers.c:171
```
size_t get_allocation_size(const void *mem)
{
    char *buf = (char*)mem - PREFIX_SIZE;
    return ((size_t*)buf)[0];
}
```

## PoC
```
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "malloc_wrappers.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if(size > 0 && data[size-1] == '\0') {
        const void *mem = (const void *)data;
        size_t allocation_size = get_allocation_size(mem);
        (void)allocation_size; // Prevent unused variable warning
    }
}

```

## crash description

- product introduce
    Nanopb is a plain-C implementation of Google's Protocol Buffers data format. 
    Github仓库地址: https://github.com/nanopb/nanopb (Star 4.1k)

- crash analyze
    "Nanopb" 存在 Heap-buffer-overflow / 越界读 漏洞
    get_allocation_size函数未校验传入的mem指针，直接减去“PREFIX_SIZE”偏移量，导致读取buf时发生越界。
    "Nanopb" has a Heap-buffer-overflow vulnerability. The `get_allocation_size` function does not check the `mem` pointer passed in, and directly subtracts the "PREFIX_SIZE" offset, resulting in an out-of-bounds error when reading `buf`.

## Crash log
```
+----------------------------------------Release Build Stacktrace----------------------------------------+
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2047161427
INFO: Loaded 1 modules   (1022 inline 8-bit counters): 1022 [0xfe1680, 0xfe1a7e),
INFO: Loaded 1 PC tables (1022 PCs): 1022 [0xf55650,0xf59630),
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/new
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/mutations
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/data-bundles/fuzzer
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 2 ft: 2 corp: 1/1b exec/s: 0 rss: 32Mb
Created link file 'fuzzer_stats'
=================================================================
==19==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000007e0 at pc 0x00000057c778 bp 0x7ffd8a837410 sp 0x7ffd8a837408
READ of size 8 at 0x6020000007e0 thread T0
SCARINESS: 33 (8-byte-read-heap-buffer-overflow-far-from-bounds)
    #0 0x57c777 in get_allocation_size /src/nanopb-0-4-9/tests/common/malloc_wrappers.c:171:12
    #1 0x57bf68 in LLVMFuzzerTestOneInput /src/fuzzer.c:12:34
    #2 0x44feb3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #3 0x44f69a in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:514:3
    #4 0x450d69 in fuzzer::Fuzzer::MutateAndTestOne() /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:757:19
    #5 0x451a35 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:895:5
    #6 0x436001 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:1112:6
    #7 0x46a252 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #8 0x7faf444a9082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/libc-start.c:308:16
    #9 0x42120d in _start

0x6020000007e0 is located 16 bytes to the left of 4-byte region [0x6020000007f0,0x6020000007f4)
allocated by thread T0 here:
    #0 0x541126 in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:69:3
    #1 0x4bfb27 in operator new(unsigned long) cxa_noexception.cpp:0
    #2 0x44f69a in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:514:3
    #3 0x450d69 in fuzzer::Fuzzer::MutateAndTestOne() /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:757:19
    #4 0x451a35 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:895:5
    #5 0x436001 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:1112:6
    #6 0x46a252 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #7 0x7faf444a9082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/libc-start.c:308:16

SUMMARY: AddressSanitizer: heap-buffer-overflow (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57c777)
Shadow bytes around the buggy address:
  0x0c047fff80a0: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
  0x0c047fff80b0: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
  0x0c047fff80c0: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
  0x0c047fff80d0: fa fa 00 fa fa fa fd fa fa fa fd fa fa fa fd fa
  0x0c047fff80e0: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
=>0x0c047fff80f0: fa fa fd fa fa fa fd fa fa fa fd fa[fa]fa 04 fa
  0x0c047fff8100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8110: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8120: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8130: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8140: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==19==ABORTING
MS: 2 InsertByte-CMP- DE: "\000\000"-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
0xdd,0xa,0x0,0x0,
\335\012\000\000
artifact_prefix='/fuzz_set/workspace/bot/inputs/fuzzer-testcases/'; Test unit written to /fuzz_set/workspace/bot/inputs/fuzzer-testcases/crash-3c9cbd377df2915b7ea41089bd80b284d851ad25
Base64: 3QoAAA==
stat::number_of_executed_units: 39
stat::average_exec_per_sec:     0
stat::new_units_added:          0
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              32


+----------------------------------------Release Build Unsymbolized Stacktrace (diff)----------------------------------------+

READ of size 8 at 0x6020000007e0 thread T0
SCARINESS: 33 (8-byte-read-heap-buffer-overflow-far-from-bounds)
    #0 0x57c777  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57c777)
    #1 0x57bf68  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57bf68)
    #2 0x44feb3  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44feb3)
    #3 0x44f69a  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44f69a)
    #4 0x450d69  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x450d69)
    #5 0x451a35  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451a35)
    #6 0x436001  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x436001)
    #7 0x46a252  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x46a252)
    #8 0x7faf444a9082  (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #9 0x42120d  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x42120d)

0x6020000007e0 is located 16 bytes to the left of 4-byte region [0x6020000007f0,0x6020000007f4)
allocated by thread T0 here:
    #0 0x541126  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x541126)
    #1 0x4bfb27  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x4bfb27)
    #2 0x44f69a  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44f69a)
    #3 0x450d69  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x450d69)
    #4 0x451a35  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451a35)
    #5 0x436001  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x436001)
    #6 0x46a252  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x46a252)
    #7 0x7faf444a9082  (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)

```

## build command
```
#!/bin/bash
find . -name "*.c" -exec $CC $CFLAGS -I./src -c {} \;
find . -name "*.o" -exec cp {} . \;

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o


$CC $CFLAGS $LIB_FUZZING_ENGINE $SRC/fuzzer.c -Wl,--whole-archive $SRC/nanopb-0-4-9/libfuzz.a -Wl,--allow-multiple-definition -I$SRC/nanopb-0-4-9/ -I$SRC/nanopb-0-4-9/tests/common -I$SRC/nanopb-0-4-9/tests/without_64bit -I$SRC/nanopb-0-4-9/examples/platformio/src -I$SRC/nanopb-0-4-9/examples/network_server -I$SRC/nanopb-0-4-9/tests/backwards_compatibility -I$SRC/nanopb-0-4-9/spm_headers/nanopb -I$SRC/nanopb-0-4-9/extra -I$SRC/nanopb-0-4-9/tests/fuzztest -I$SRC/nanopb-0-4-9/spm_headers  -o $OUT/fuzzer
```

## Fuzz instruction
```
[Environment] ASAN_OPTIONS=alloc_dealloc_mismatch=0:allocator_may_return_null=1:allocator_release_to_os_interval_ms=500:allow_user_segv_handler=0:check_malloc_usable_size=0:detect_leaks=1:detect_odr_violation=0:detect_stack_use_after_return=1:exitcode=77:fast_unwind_on_fatal=0:handle_abort=2:handle_segv=2:handle_sigbus=2:handle_sigfpe=2:handle_sigill=2:max_uar_stack_size_log=16:print_scariness=1:print_summary=1:print_suppressions=0:quarantine_size_mb=64:strict_memcmp=1:symbolize=0:use_sigaltstack=1
```

```
["/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer","-timeout=25","-rss_limit_mb=2560","-artifact_prefix=/fuzz_set/workspace/bot/inputs/fuzzer-testcases/","-max_total_time=6300","-print_final_stats=1","/fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/new","/fuzz_set/workspace/bot/inputs/data-bundles/fuzzer"]
```

