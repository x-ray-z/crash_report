

## crash type

AddressSanitizer: SEGV on unknown address  
CWE-476: NULL Pointer Dereference

## project & version

https://github.com/nanopb/nanopb  
0.4.9

## crash position

in advance_iterator /src/pb_common.c:126
```
static void advance_iterator(pb_field_iter_t *iter)
{
    iter->index++;

    if (iter->index >= iter->descriptor->field_count) //crash
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
#include "pb_decode.h"
#include "pb_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    pb_field_iter_t iter;
    const uint8_t *fuzz_data = data;
    size_t fuzz_size = size;
    if (size > 0 && data[size - 1] == 0) {
        fuzz_size--;
        fuzz_data++;
    }
    pb_istream_t stream = pb_istream_from_buffer(fuzz_data, fuzz_size);
    pb_field_iter_t *iter_ptr = (pb_field_iter_t *)&iter;
    pb_field_t fields[] = {{0,0,0,0,0,0,0,0}};
    pb_decode(&stream, fields, NULL);
    bool result = pb_field_iter_next(iter_ptr);
    (void)result;
}

```

## crash description

The `pb_field_iter_next` and `advance_iterator` functions do not verify whether the passed pointer is NULL, resulting in a NULL pointer dereference.

## Crash log
```
+----------------------------------------Release Build Stacktrace----------------------------------------+
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 230011547
INFO: Loaded 1 modules   (984 inline 8-bit counters): 984 [0xfe0360, 0xfe0738),
INFO: Loaded 1 PC tables (984 PCs): 984 [0xf552f0,0xf59070),
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/new
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/mutations
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/data-bundles/fuzzer
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
AddressSanitizer:DEADLYSIGNAL
=================================================================
==19==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000020 (pc 0x00000057cd24 bp 0x7ffc716480b0 sp 0x7ffc71648060 T0)
Created link file 'fuzzer_stats'
==19==The signal is caused by a READ memory access.
==19==Hint: address points to the zero page.
SCARINESS: 10 (null-deref)
    #0 0x57cd24 in advance_iterator /src/nanopb-0-4-9/pb_common.c:126:42
    #1 0x57cd24 in pb_field_iter_next /src/nanopb-0-4-9/pb_common.c:190:5
    #2 0x57c080 in LLVMFuzzerTestOneInput /src/fuzzer.c:23:19
    #3 0x44fea3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #4 0x451254 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:804:3
    #5 0x451729 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:857:3
    #6 0x435ff1 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:1112:6
    #7 0x46a242 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #8 0x7f95cdbc0082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/libc-start.c:308:16
    #9 0x4211fd in _start

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57cd24)
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

==19==Hint: address points to the zero page.
SCARINESS: 10 (null-deref)
    #0 0x57cd24  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57cd24)
    #1 0x57c080  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57c080)
    #2 0x44fea3  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44fea3)
    #3 0x451254  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451254)
    #4 0x451729  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451729)
    #5 0x435ff1  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x435ff1)
    #6 0x46a242  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x46a242)
    #7 0x7f95cdbc0082  (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #8 0x4211fd  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x4211fd)

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

