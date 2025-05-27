

## crash type

Heap-buffer-overflow

## project & version

https://github.com/nanopb/nanopb  
0.4.9

## crash position

#0 0x57c8b6 in load_descriptor_values /nanopb/pb_common.c:line 17:
```
static bool load_descriptor_values(pb_field_iter_t *iter)
{
    uint32_t word0;
    uint32_t data_offset;
    int_least8_t size_offset;

    if (iter->index >= iter->descriptor->field_count)
        return false;

    word0 = PB_PROGMEM_READU32(iter->descriptor->field_info[iter->field_info_index]); //crash
    ...
}
```

## PoC
```
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pb.h"
#include "pb_encode.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const pb_msgdesc_t *fields;
    const void *src_struct;
    size_t *size_ptr = (size_t *)malloc(sizeof(size_t));

    // Assuming data contains serialized fields and src_struct
    // This is a placeholder for deserialization logic
    // Deserialization logic will depend on the actual pb_msgdesc_t used in the application
    // For this example, we assume that the data is properly formatted and can be cast directly
    fields = (const pb_msgdesc_t *)data;
    src_struct = (const void *)(data + sizeof(pb_msgdesc_t));

    pb_get_encoded_size(size_ptr, fields, src_struct);

    free(size_ptr);
}

```

## crash description

When the `load_descriptor_values` ​​function accesses the `iter->descriptor->field_info` array, the validity of the array index `iter->field_info_index` is not verified, and a memory address beyond the array boundary is accessed.

## Crash log
```
+----------------------------------------Release Build Stacktrace----------------------------------------+
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 343787493
INFO: Loaded 1 modules   (981 inline 8-bit counters): 981 [0xfdf360, 0xfdf735),
INFO: Loaded 1 PC tables (981 PCs): 981 [0xf542b0,0xf58000),
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/new
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/data-bundles/fuzzer
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
=================================================================
==19==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000b0 at pc 0x00000057c8b7 bp 0x7ffd6e533530 sp 0x7ffd6e533528
Created link file 'fuzzer_stats'
READ of size 8 at 0x6020000000b0 thread T0
SCARINESS: 23 (8-byte-read-heap-buffer-overflow)
    #0 0x57c8b6 in load_descriptor_values /src/nanopb-0-4-9/pb_common.c:17:13
    #1 0x57d9cb in pb_field_iter_begin /src/nanopb-0-4-9/pb_common.c:163:12
    #2 0x57d9cb in pb_field_iter_begin_const /src/nanopb-0-4-9/pb_common.c:292:12
    #3 0x5881ec in pb_encode /src/nanopb-0-4-9/pb_encode.c:515:10
    #4 0x58a0bb in pb_get_encoded_size /src/nanopb-0-4-9/pb_encode.c:561:10
    #5 0x57bf1c in LLVMFuzzerTestOneInput /src/fuzzer.c:22:5
    #6 0x44fea3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #7 0x451254 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:804:3
    #8 0x451729 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:857:3
    #9 0x435ff1 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:1112:6
    #10 0x46a242 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #11 0x7fb77f475082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/libc-start.c:308:16
    #12 0x4211fd in _start

0x6020000000b1 is located 0 bytes to the right of 1-byte region [0x6020000000b0,0x6020000000b1)
allocated by thread T0 here:
    #0 0x541116 in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:69:3
    #1 0x4bfb17 in operator new(unsigned long) cxa_noexception.cpp:0
    #2 0x451254 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:804:3
    #3 0x451729 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:857:3
    #4 0x435ff1 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:1112:6
    #5 0x46a242 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #6 0x7fb77f475082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/libc-start.c:308:16

SUMMARY: AddressSanitizer: heap-buffer-overflow (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57c8b6)
Shadow bytes around the buggy address:
  0x0c047fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff8000: fa fa 00 00 fa fa 00 fa fa fa 00 fa fa fa 00 fa
=>0x0c047fff8010: fa fa 00 fa fa fa[01]fa fa fa 00 fa fa fa fa fa
  0x0c047fff8020: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8060: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
MS: 0 ; base unit: 0000000000000000000000000000000000000000


artifact_prefix='/fuzz_set/workspace/bot/inputs/fuzzer-testcases/'; Test unit written to /fuzz_set/workspace/bot/inputs/fuzzer-testcases/crash-da39a3ee5e6b4b0d3255bfef95601890afd80709
Base64:
stat::number_of_executed_units: 1
stat::average_exec_per_sec:     0
stat::new_units_added:          0
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              32


+----------------------------------------Release Build Unsymbolized Stacktrace (diff)----------------------------------------+

READ of size 8 at 0x6020000000b0 thread T0
SCARINESS: 23 (8-byte-read-heap-buffer-overflow)
    #0 0x57c8b6  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57c8b6)
    #1 0x57d9cb  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57d9cb)
    #2 0x5881ec  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x5881ec)
    #3 0x58a0bb  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x58a0bb)
    #4 0x57bf1c  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57bf1c)
    #5 0x44fea3  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44fea3)
    #6 0x451254  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451254)
    #7 0x451729  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451729)
    #8 0x435ff1  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x435ff1)
    #9 0x46a242  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x46a242)
    #10 0x7fb77f475082  (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #11 0x4211fd  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x4211fd)

0x6020000000b1 is located 0 bytes to the right of 1-byte region [0x6020000000b0,0x6020000000b1)
allocated by thread T0 here:
    #0 0x541116  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x541116)
    #1 0x4bfb17  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x4bfb17)
    #2 0x451254  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451254)
    #3 0x451729  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451729)
    #4 0x435ff1  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x435ff1)
    #5 0x46a242  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x46a242)
    #6 0x7fb77f475082  (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)

```
## build command
```
#!/bin/bash
for file in "pb_decode.c pb_common.c pb_encode.c"; do
  $CC $CFLAGS -c ${file}
done

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