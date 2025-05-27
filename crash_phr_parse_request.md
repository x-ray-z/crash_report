

## crash type

AddressSanitizer: SEGV on unknown address  
CWE-476: NULL Pointer Dereference

## project & version

https://github.com/h2o/picohttpparser  
(latest)f8d0513f1a7a111f2597d643b073935a8afaf9e5

## crash position

picohttpparser/picohttpparser.c: line 204
```
static const char *is_complete(const char *buf, const char *buf_end, size_t last_len, int *ret)
{
    int ret_cnt = 0;
    buf = last_len < 3 ? buf : buf + last_len - 3;

    while (1) {
        CHECK_EOF();
        if (*buf == '\015') { //crash
    ...
}}}
```

## crash description

Neither the `phr_parse_request` function nor the `is_complete` function validates the `buf` parameter: When parsing an HTTP request, if the input buffer pointer `buf` is NULL, the function does not correctly validate the pointer, which will lead to access to an illegal memory address and trigger a crash.

## PoC
```
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "picohttpparser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const char *request = (const char *)data;
  size_t request_length = size;
  const char *method = NULL;
  size_t method_len = 0;
  const char *url = NULL;
  size_t url_len = 0;
  int version = 0;
  struct phr_header headers[10];
  size_t num_headers = 10;
  size_t pos = 0;

  int ret = phr_parse_request(request, request_length, &method, &method_len, &url, &url_len, &version, headers, &num_headers, &pos);
  (void)ret;
  (void)method;
  (void)method_len;
  (void)url;
  (void)url_len;
  (void)version;
  (void)headers;
  (void)num_headers;
  (void)pos;

  return 0;
}
```  

## crashlog
```
+----------------------------------------Release Build Stacktrace----------------------------------------+
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3175824923
INFO: Loaded 1 modules   (252 inline 8-bit counters): 252 [0xfce9e0, 0xfceadc),
INFO: Loaded 1 PC tables (252 PCs): 252 [0xf47a30,0xf489f0),
INFO: -fork=2: fuzzing in separate process(s)
INFO: -fork=2: 0 seed inputs, starting to fuzz in /fuzz_set/workspace/bot_tmpdir/libFuzzerTemp.FuzzWithFork19.dir
#1: cov: 0 ft: 0 corp: 0 exec/s 0 oom/timeout/crash: 0/0/0 time: 0s job: 2 dft_time: 0
INFO: log from the inner process:
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3175899041
INFO: Loaded 1 modules   (252 inline 8-bit counters): 252 [0xfce9e0, 0xfceadc),
INFO: Loaded 1 PC tables (252 PCs): 252 [0xf47a30,0xf489f0),
INFO:        0 files found in /fuzz_set/workspace/bot_tmpdir/libFuzzerTemp.FuzzWithFork19.dir/C2
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
AddressSanitizer:DEADLYSIGNAL
=================================================================
==27==ERROR: AddressSanitizer: SEGV on unknown address 0x1be818c8555f (pc 0x00000057c7e9 bp 0x7ffc8c2fb030 sp 0x7ffc8c2faf40 T0)
==27==The signal is caused by a READ memory access.
Created link file 'fuzzer_stats'
SCARINESS: 20 (wild-addr-read)
    #0 0x57c7e9 in is_complete /src/picohttpparser-master/picohttpparser.c:204:13
    #1 0x57c7e9 in phr_parse_request /src/picohttpparser-master/picohttpparser.c:417:26
    #2 0x57c159 in LLVMFuzzerTestOneInput /src/fuzzer.c:21:13
    #3 0x44feb3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #4 0x451264 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:804:3
    #5 0x451739 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:857:3
    #6 0x436001 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:1112:6
    #7 0x46a252 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #8 0x7f1cc68b0082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/libc-start.c:308:16
    #9 0x42120d in _start

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57c7e9)
==27==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000


artifact_prefix='/fuzz_set/workspace/bot/inputs/fuzzer-testcases/'; Test unit written to /fuzz_set/workspace/bot/inputs/fuzzer-testcases/crash-da39a3ee5e6b4b0d3255bfef95601890afd80709
Base64:
stat::number_of_executed_units: 1
stat::average_exec_per_sec:     0
stat::new_units_added:          0
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              31
INFO: exiting: 77 time: 0s


+----------------------------------------Release Build Unsymbolized Stacktrace (diff)----------------------------------------+

Created link file 'fuzzer_stats'
SCARINESS: 20 (wild-addr-read)
    #0 0x57c7e9  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57c7e9)
    #1 0x57c159  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57c159)
    #2 0x44feb3  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44feb3)
    #3 0x451264  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451264)
    #4 0x451739  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451739)
    #5 0x436001  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x436001)
    #6 0x46a252  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x46a252)
    #7 0x7f1cc68b0082  (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #8 0x42120d  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x42120d)
```

## build command

```
#!/bin/bash
for file in "bench.c picohttpparser.c"; do
  $CC $CFLAGS -c ${file}
done

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o


$CC $CFLAGS $LIB_FUZZING_ENGINE $SRC/fuzzer.c -Wl,--whole-archive $SRC/picohttpparser-master/libfuzz.a -Wl,--allow-multiple-definition -I$SRC/picohttpparser-master/  -o $OUT/fuzzer
```

## Fuzz instruction
```
[Environment] ASAN_OPTIONS=alloc_dealloc_mismatch=0:allocator_may_return_null=1:allocator_release_to_os_interval_ms=500:allow_user_segv_handler=0:check_malloc_usable_size=0:detect_leaks=1:detect_odr_violation=0:detect_stack_use_after_return=1:exitcode=77:fast_unwind_on_fatal=0:handle_abort=2:handle_segv=2:handle_sigbus=2:handle_sigfpe=2:handle_sigill=2:max_uar_stack_size_log=16:print_scariness=1:print_summary=1:print_suppressions=0:quarantine_size_mb=64:strict_memcmp=1:symbolize=0:use_sigaltstack=1
```

```
["/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer","-timeout=25","-rss_limit_mb=2560","-fork=2","-artifact_prefix=/fuzz_set/workspace/bot/inputs/fuzzer-testcases/","-max_total_time=5600","-print_final_stats=1","/fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/new","/fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/mutations","/fuzz_set/workspace/bot/inputs/data-bundles/fuzzer"]
```