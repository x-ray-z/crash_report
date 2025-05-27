

## crash type

Stack-use-after-scope

## project & version

https://github.com/libimobiledevice/libplist  
test version: (2024/10/23)a5df0a66409e565a46f6f73f988d3496b991c7c0  
affected version: version <= 2.7.0(latest)

## crash position

in mktime64 /libplist/src/time64.c:512
```
Time64_T mktime64(struct TM *input_date) {
    struct tm safe_date;
    struct TM date;
    Time64_T  timev;
    Year      year = input_date->tm_year + 1900; //crash here
    ...
}
```

## PoC
```
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "time64.h"
struct tm* parseTM(const uint8_t *data, size_t size) {
    char *tmStr = (char*)data;
    tmStr[size] = '\0'; // Ensure null-terminated
    struct tm tm;
    memset(&tm, 0, sizeof(struct tm));
    sscanf(tmStr, "%d %d %d %d %d %d", 
           &tm.tm_year, &tm.tm_mon, &tm.tm_mday, 
           &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    tm.tm_year -= 1900; // mktime requires year since 1900
    tm.tm_mon--; // mktime requires month to be 0-11
    return &tm;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct tm *input_date = parseTM(data, size);
    Time64_T result = mktime64(input_date);
    // You can add checks or assertions here if needed
    // Remember to free any dynamically allocated memory
    return 0;
}

```

## crash description

The `mktime64` function does not verify the input parameter `input_date`, resulting in access to invalid stack memory.

## Crash log
```
+----------------------------------------Release Build Stacktrace----------------------------------------+
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 783477380
INFO: Loaded 1 modules   (426 inline 8-bit counters): 426 [0xfd30e0, 0xfd328a),
INFO: Loaded 1 PC tables (426 PCs): 426 [0xf4a570,0xf4c010),
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/new
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/mutations
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/data-bundles/fuzzer
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
=================================================================
==19==ERROR: AddressSanitizer: stack-use-after-scope on address 0x7f3afe65f834 at pc 0x0000005810d4 bp 0x7ffd1e32cf10 sp 0x7ffd1e32cf08
READ of size 4 at 0x7f3afe65f834 thread T0
Created link file 'fuzzer_stats'
SCARINESS: 17 (4-byte-read-stack-use-after-scope)
    #0 0x5810d3 in mktime64 /src/libplist-master/src/time64.c:512:34
    #1 0x57c2a2 in LLVMFuzzerTestOneInput /src/fuzzer.c:28:23
    #2 0x44feb3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #3 0x451264 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:804:3
    #4 0x451739 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:857:3
    #5 0x436001 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:1112:6
    #6 0x46a252 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #7 0x7f3afedd7082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/libc-start.c:308:16
    #8 0x42120d in _start

Address 0x7f3afe65f834 is located in stack of thread T0 at offset 52 in frame
    #0 0x57c11f in LLVMFuzzerTestOneInput /src/fuzzer.c:26

  This frame has 1 object(s):
    [32, 88) 'tm.i' (line 12) <== Memory access at offset 52 is inside this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-use-after-scope (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x5810d3)
Shadow bytes around the buggy address:
  0x0fe7dfcc3eb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe7dfcc3ec0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe7dfcc3ed0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe7dfcc3ee0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe7dfcc3ef0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0fe7dfcc3f00: f1 f1 f1 f1 f8 f8[f8]f8 f8 f8 f8 f3 f3 f3 f3 f3
  0x0fe7dfcc3f10: f1 f1 f1 f1 00 00 00 00 00 00 00 f3 f3 f3 f3 f3
  0x0fe7dfcc3f20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe7dfcc3f30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe7dfcc3f40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe7dfcc3f50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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

Created link file 'fuzzer_stats'
SCARINESS: 17 (4-byte-read-stack-use-after-scope)
    #0 0x5810d3  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x5810d3)
    #1 0x57c2a2  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57c2a2)
    #2 0x44feb3  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44feb3)
    #3 0x451264  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451264)
    #4 0x451739  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451739)
    #5 0x436001  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x436001)
    #6 0x46a252  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x46a252)
    #7 0x7f3afedd7082  (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #8 0x42120d  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x42120d)

Address 0x7f3afe65f834 is located in stack of thread T0 at offset 52 in frame
    #0 0x57c11f  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57c11f)

```

## build command

```
#!/bin/bash
find . -name "*.c" -exec $CC $CFLAGS -I./src -c {} \;
find . -name "*.o" -exec cp {} . \;

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o


$CC $CFLAGS $LIB_FUZZING_ENGINE $SRC/fuzzer.c -Wl,--whole-archive $SRC/libplist-master/libfuzz.a -Wl,--allow-multiple-definition -I$SRC/libplist-master/src -I$SRC/libplist-master/libcnary/include -I$SRC/libplist-master/include/plist -I$SRC/libplist-master/cython  -o $OUT/fuzzer
```

## Fuzz instruction
```
[Environment] ASAN_OPTIONS=alloc_dealloc_mismatch=0:allocator_may_return_null=1:allocator_release_to_os_interval_ms=500:allow_user_segv_handler=0:check_malloc_usable_size=0:detect_leaks=1:detect_odr_violation=0:detect_stack_use_after_return=1:exitcode=77:fast_unwind_on_fatal=0:handle_abort=2:handle_segv=2:handle_sigbus=2:handle_sigfpe=2:handle_sigill=2:max_uar_stack_size_log=16:print_scariness=1:print_summary=1:print_suppressions=0:quarantine_size_mb=64:strict_memcmp=1:symbolize=0:use_sigaltstack=1
```

```
["/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer","-timeout=25","-rss_limit_mb=2560","-artifact_prefix=/fuzz_set/workspace/bot/inputs/fuzzer-testcases/","-max_total_time=5700","-print_final_stats=1","/fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/new","/fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/mutations","/fuzz_set/workspace/bot/inputs/data-bundles/fuzzer"]
```

