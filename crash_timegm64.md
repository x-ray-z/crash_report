

## crash type

global-buffer-overflow

## project & version

https://github.com/libimobiledevice/libplist  
test version: (2024/10/23)a5df0a66409e565a46f6f73f988d3496b991c7c0  
affected version: version <= 2.7.0(latest)

## crash position

in timegm64 /libplist/src/time64.c:252
```
Time64_T timegm64(const struct TM *date) {
    Time64_T days    = 0;
    Time64_T seconds = 0;
    Year     year;
    Year     orig_year = (Year)date->tm_year;
    int      cycles  = 0;

    if( (orig_year > 100) || (orig_year < -300) ) {
        cycles = (orig_year - 100) / 400;
        orig_year -= cycles * 400;
        days      += (Time64_T)cycles * days_in_gregorian_cycle;
    }
    TIME64_TRACE3("# timegm/ cycles: %d, days: %lld, orig_year: %lld\n", cycles, days, orig_year);

    if( orig_year > 70 ) {
        year = 70;
        while( year < orig_year ) {
            days += length_of_year[IS_LEAP(year)];
            year++;
        }
    }
    else if ( orig_year < 70 ) {
        year = 69;
        do {
            days -= length_of_year[IS_LEAP(year)];
            year--;
        } while( year >= orig_year );
    }

    days += julian_days_by_month[IS_LEAP(orig_year)][date->tm_mon]; //crash here
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

struct tm* parse_tm(const uint8_t *data, size_t size) {
    if (size < sizeof(struct tm)) return NULL;
    struct tm *tm = (struct tm*)malloc(sizeof(struct tm));
    memcpy(tm, data, sizeof(struct tm));
    return tm;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct tm* tm = parse_tm(data, size);
    if (tm == NULL) return 0;
    Time64_T result = timegm64(tm);
    free(tm);
    return 0;
}

```

## crash description

The `timegm64` function does not validate the input parameter `date`, resulting in an out-of-bounds read when accessing the global variable `julian_days_by_month`.

## Crash log1
```
+----------------------------------------Release Build Stacktrace----------------------------------------+
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 154600254
INFO: Loaded 1 modules   (432 inline 8-bit counters): 432 [0xfd30a0, 0xfd3250),
INFO: Loaded 1 PC tables (432 PCs): 432 [0xf4a4f0,0xf4bff0),
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/new
Created link file 'fuzzer_stats'
INFO:     1991 files found in /fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/mutations
INFO:        9 files found in /fuzz_set/workspace/bot/inputs/data-bundles/fuzzer
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 65906 bytes
INFO: seed corpus: files: 2000 min: 1b max: 65906b total: 985812b rss: 33Mb
=================================================================
==9649==ERROR: AddressSanitizer: global-buffer-overflow on address 0x00000078b57e at pc 0x000000580344 bp 0x7ffe49ca83a0 sp 0x7ffe49ca8398
READ of size 2 at 0x00000078b57e thread T0
SCARINESS: 14 (2-byte-read-global-buffer-overflow)
    #0 0x580343 in timegm64 /src/libplist-master/src/time64.c:252:13
    #1 0x57bfb1 in LLVMFuzzerTestOneInput /src/fuzzer.c:19:23
    #2 0x44feb3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #3 0x44f69a in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:514:3
    #4 0x451504 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:826:7
    #5 0x451739 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:857:3
    #6 0x436001 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:1112:6
    #7 0x46a252 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #8 0x7f5a35f4c082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/libc-start.c:308:16
    #9 0x42120d in _start

0x00000078b57e is located 2 bytes to the left of global variable 'julian_days_by_month' defined in './src/time64.c:57:20' (0x78b580) of size 48
0x00000078b57e is located 26 bytes to the right of global variable 'length_of_year' defined in './src/time64.c:71:20' (0x78b560) of size 4
SUMMARY: AddressSanitizer: global-buffer-overflow (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x580343)
Shadow bytes around the buggy address:
  0x0000800e9650: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800e9660: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800e9670: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800e9680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800e9690: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0000800e96a0: 00 00 00 00 00 00 00 00 00 00 00 00 04 f9 f9[f9]
  0x0000800e96b0: 00 00 00 00 00 00 f9 f9 f9 f9 f9 f9 00 02 f9 f9
  0x0000800e96c0: 00 07 f9 f9 00 00 00 00 00 00 05 f9 f9 f9 f9 f9
  0x0000800e96d0: 00 00 00 f9 f9 f9 f9 f9 00 00 01 f9 f9 f9 f9 f9
  0x0000800e96e0: 00 00 00 00 00 00 00 f9 f9 f9 f9 f9 00 00 00 00
  0x0000800e96f0: f9 f9 f9 f9 00 00 00 04 f9 f9 f9 f9 00 00 00 00
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
==9649==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000
0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xa,0xa,0xff,0xff,0xff,0xff,0xff,0xa,0xa,0xa,
\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\012\012\377\377\377\377\377\012\012\012
artifact_prefix='/fuzz_set/workspace/bot/inputs/fuzzer-testcases/'; Test unit written to /fuzz_set/workspace/bot/inputs/fuzzer-testcases/crash-0682aa39b062f5368446efbda8400093b6281d49
Base64: /////////////////////////////////////////////////////////////woK//////8KCgo=
stat::number_of_executed_units: 1492
stat::average_exec_per_sec:     0
stat::new_units_added:          0
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              54


+----------------------------------------Release Build Unsymbolized Stacktrace (diff)----------------------------------------+

READ of size 2 at 0x00000078b57e thread T0
SCARINESS: 14 (2-byte-read-global-buffer-overflow)
    #0 0x580343  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x580343)
    #1 0x57bfb1  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57bfb1)
    #2 0x44feb3  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44feb3)
    #3 0x44f69a  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44f69a)
    #4 0x451504  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451504)
    #5 0x451739  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451739)
    #6 0x436001  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x436001)
    #7 0x46a252  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x46a252)
    #8 0x7f5a35f4c082  (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #9 0x42120d  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x42120d)

```

## Crash log2
```
+----------------------------------------Release Build Stacktrace----------------------------------------+
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 4209503019
INFO: Loaded 1 modules   (432 inline 8-bit counters): 432 [0xfd30a0, 0xfd3250),
INFO: Loaded 1 PC tables (432 PCs): 432 [0xf4a4f0,0xf4bff0),
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/new
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/mutations
INFO:        0 files found in /fuzz_set/workspace/bot/inputs/data-bundles/fuzzer
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 3 ft: 5 corp: 1/1b exec/s: 0 rss: 32Mb
Created link file 'fuzzer_stats'
#4	NEW    cov: 3 ft: 6 corp: 2/4b lim: 4 exec/s: 0 rss: 32Mb L: 3/3 MS: 2 CrossOver-CrossOver-
#417	NEW    cov: 3 ft: 7 corp: 3/11b lim: 8 exec/s: 0 rss: 32Mb L: 7/7 MS: 3 InsertRepeatedBytes-ShuffleBytes-InsertByte-
#426	NEW    cov: 3 ft: 8 corp: 4/19b lim: 8 exec/s: 0 rss: 32Mb L: 8/8 MS: 4 InsertByte-ChangeByte-InsertRepeatedBytes-CrossOver-
#745	NEW    cov: 3 ft: 9 corp: 5/28b lim: 11 exec/s: 0 rss: 32Mb L: 9/9 MS: 4 EraseBytes-ChangeBit-InsertRepeatedBytes-CrossOver-
#2226	NEW    cov: 3 ft: 10 corp: 6/52b lim: 25 exec/s: 0 rss: 32Mb L: 24/24 MS: 1 InsertRepeatedBytes-
#2247	NEW    cov: 3 ft: 11 corp: 7/77b lim: 25 exec/s: 0 rss: 32Mb L: 25/25 MS: 1 CopyPart-
#4071	NEW    cov: 3 ft: 12 corp: 8/119b lim: 43 exec/s: 0 rss: 32Mb L: 42/42 MS: 4 InsertRepeatedBytes-ShuffleBytes-CopyPart-InsertRepeatedBytes-
#4549	REDUCE cov: 3 ft: 12 corp: 8/118b lim: 43 exec/s: 0 rss: 32Mb L: 41/41 MS: 3 EraseBytes-InsertByte-CopyPart-
#5560	NEW    cov: 3 ft: 13 corp: 9/167b lim: 53 exec/s: 0 rss: 32Mb L: 49/49 MS: 1 InsertRepeatedBytes-
#5613	REDUCE cov: 3 ft: 14 corp: 10/220b lim: 53 exec/s: 0 rss: 32Mb L: 53/53 MS: 3 InsertRepeatedBytes-InsertRepeatedBytes-CrossOver-
AddressSanitizer:DEADLYSIGNAL
=================================================================
==19==ERROR: AddressSanitizer: SEGV on unknown address 0x00009cf8c0da (pc 0x00000058024e bp 0x7ffcee34f690 sp 0x7ffcee34f650 T0)
==19==The signal is caused by a READ memory access.
SCARINESS: 20 (wild-addr-read)
    #0 0x58024e in timegm64 /src/libplist-master/src/time64.c:252:13
    #1 0x57bfb1 in LLVMFuzzerTestOneInput /src/fuzzer.c:19:23
    #2 0x44feb3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #3 0x44f69a in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:514:3
    #4 0x450d69 in fuzzer::Fuzzer::MutateAndTestOne() /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:757:19
    #5 0x451a35 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:895:5
    #6 0x436001 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:1112:6
    #7 0x46a252 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #8 0x7fb8d9998082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/libc-start.c:308:16
    #9 0x42120d in _start

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x58024e)
==19==ABORTING
MS: 3 CopyPart-CopyPart-InsertRepeatedBytes-; base unit: 88a818c13085b85b9a86df80caf689180d13c81b
0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa8,0xa,
\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250sssssssssss\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\250\012
artifact_prefix='/fuzz_set/workspace/bot/inputs/fuzzer-testcases/'; Test unit written to /fuzz_set/workspace/bot/inputs/fuzzer-testcases/crash-9a885393658fd583b775aeecddab808eaff2e162
Base64: qKioqKioqKioqKioqKioqKioqHNzc3Nzc3Nzc3NzqKioqKioqKioqKioqKioqKioqKioqKioqKgK
stat::number_of_executed_units: 6126
stat::average_exec_per_sec:     0
stat::new_units_added:          10
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              32


+----------------------------------------Release Build Unsymbolized Stacktrace (diff)----------------------------------------+

==19==The signal is caused by a READ memory access.
SCARINESS: 20 (wild-addr-read)
    #0 0x58024e  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x58024e)
    #1 0x57bfb1  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57bfb1)
    #2 0x44feb3  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44feb3)
    #3 0x44f69a  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44f69a)
    #4 0x450d69  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x450d69)
    #5 0x451a35  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451a35)
    #6 0x436001  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x436001)
    #7 0x46a252  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x46a252)
    #8 0x7fb8d9998082  (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #9 0x42120d  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x42120d)

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