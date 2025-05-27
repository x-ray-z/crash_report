
## crash type

Global-buffer-overflow

## project && version

https://github.com/uber/h3  
4.0.0

## crash position

in areNeighborCells /h3-4-0-0/src/h3lib/lib/directedEdge.c:86 
```
H3Error H3_EXPORT(areNeighborCells)(H3Index origin, H3Index destination,
                                    int *out) {
    if (H3_GET_MODE(origin) != H3_CELL_MODE ||
        H3_GET_MODE(destination) != H3_CELL_MODE) {
        return E_CELL_INVALID;
    }

    if (origin == destination) {
        *out = 0;
        return E_SUCCESS;
    }

    if (H3_GET_RESOLUTION(origin) != H3_GET_RESOLUTION(destination)) {
        return E_RES_MISMATCH;
    }

    int parentRes = H3_GET_RESOLUTION(origin) - 1;
    if (parentRes > 0) {
        // TODO: Return error codes here
        H3Index originParent;
        H3_EXPORT(cellToParent)(origin, parentRes, &originParent);
        H3Index destinationParent;
        H3_EXPORT(cellToParent)(destination, parentRes, &destinationParent);
        if (originParent == destinationParent) {
            Direction originResDigit =
                H3_GET_INDEX_DIGIT(origin, parentRes + 1);
            Direction destinationResDigit =
                H3_GET_INDEX_DIGIT(destination, parentRes + 1);
            if (originResDigit == CENTER_DIGIT ||
                destinationResDigit == CENTER_DIGIT) {
                *out = 1;
                return E_SUCCESS;
            }
            // These sets are the relevant neighbors in the clockwise
            // and counter-clockwise
            const Direction neighborSetClockwise[] = {
                CENTER_DIGIT,  JK_AXES_DIGIT, IJ_AXES_DIGIT, J_AXES_DIGIT,
                IK_AXES_DIGIT, K_AXES_DIGIT,  I_AXES_DIGIT};
            const Direction neighborSetCounterclockwise[] = {
                CENTER_DIGIT,  IK_AXES_DIGIT, JK_AXES_DIGIT, K_AXES_DIGIT,
                IJ_AXES_DIGIT, I_AXES_DIGIT,  J_AXES_DIGIT};
            if (neighborSetClockwise[originResDigit] == destinationResDigit ||   // crash here 
            ......
```

## PoC
```
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "algos.h"
#include "h3Index.h"
#include "args.h"
#include "constants.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0; // Minimum size for two H3Index arguments and an int pointer
    const uint8_t *ptr = data;
    H3Index origin = *(uint64_t *)ptr;
    ptr += sizeof(uint64_t);
    H3Index destination = *(uint64_t *)ptr;
    ptr += sizeof(uint64_t);
    int out;
    H3Error result = areNeighborCells(origin, destination, &out);
    // At this point, you can add more checks or assertions if necessary
    return 0;
}

```

## crash description

Function `areNeighborCells` lacks a check for the input param `origin`, which may lead to `Global-buffer-overflow` crash when access `neighborSetCounterclockwise` array.

## crashlog
```
3	REDUCE cov: 146 ft: 1397 corp: 337/6107b lim: 1466 exec/s: 127706 rss: 133Mb L: 20/239 MS: 1 EraseBytes-
#255659	REDUCE cov: 146 ft: 1397 corp: 337/6105b lim: 1466 exec/s: 127829 rss: 133Mb L: 16/239 MS: 1 EraseBytes-
#258675	NEW    cov: 146 ft: 1399 corp: 338/6126b lim: 1496 exec/s: 129337 rss: 133Mb L: 21/239 MS: 1 ChangeBinInt-
#262144	pulse  cov: 146 ft: 1399 corp: 338/6126b lim: 1526 exec/s: 131072 rss: 133Mb
#263046	REDUCE cov: 146 ft: 1399 corp: 338/6124b lim: 1536 exec/s: 131523 rss: 133Mb L: 16/239 MS: 1 EraseBytes-
#266287	NEW    cov: 146 ft: 1402 corp: 339/6141b lim: 1566 exec/s: 133143 rss: 133Mb L: 17/239 MS: 1 ChangeByte-
#266288	REDUCE cov: 146 ft: 1403 corp: 340/6158b lim: 1566 exec/s: 133144 rss: 133Mb L: 17/239 MS: 1 ChangeBit-
#266432	REDUCE cov: 146 ft: 1404 corp: 341/6204b lim: 1566 exec/s: 133216 rss: 133Mb L: 46/239 MS: 4 ChangeByte-ChangeByte-InsertRepeatedBytes-CMP- DE: "\001\000"-
#267543	REDUCE cov: 146 ft: 1405 corp: 342/6220b lim: 1576 exec/s: 133771 rss: 133Mb L: 16/239 MS: 1 ChangeByte-
#267855	REDUCE cov: 146 ft: 1405 corp: 342/6218b lim: 1576 exec/s: 133927 rss: 133Mb L: 17/239 MS: 2 ShuffleBytes-EraseBytes-
#268901	REDUCE cov: 146 ft: 1405 corp: 342/6217b lim: 1586 exec/s: 134450 rss: 133Mb L: 16/239 MS: 1 EraseBytes-
#268952	REDUCE cov: 146 ft: 1405 corp: 342/6216b lim: 1586 exec/s: 134476 rss: 133Mb L: 18/239 MS: 1 EraseBytes-
#269409	REDUCE cov: 146 ft: 1405 corp: 342/6214b lim: 1586 exec/s: 134704 rss: 133Mb L: 44/239 MS: 2 ChangeBinInt-EraseBytes-
#274220	REDUCE cov: 146 ft: 1405 corp: 342/6210b lim: 1626 exec/s: 137110 rss: 133Mb L: 40/239 MS: 1 EraseBytes-
#274222	REDUCE cov: 146 ft: 1405 corp: 342/6209b lim: 1626 exec/s: 137111 rss: 133Mb L: 16/239 MS: 2 ShuffleBytes-EraseBytes-
#274468	REDUCE cov: 146 ft: 1405 corp: 342/6189b lim: 1626 exec/s: 137234 rss: 133Mb L: 20/239 MS: 1 EraseBytes-
#274955	REDUCE cov: 146 ft: 1405 corp: 342/6185b lim: 1626 exec/s: 137477 rss: 133Mb L: 21/239 MS: 2 PersAutoDict-EraseBytes- DE: "\377G"-
#277429	NEW    cov: 146 ft: 1406 corp: 343/6201b lim: 1646 exec/s: 138714 rss: 133Mb L: 16/239 MS: 4 PersAutoDict-ChangeBinInt-ChangeBit-CMP- DE: "\377\377\377\377"-"\014\377\012\376\005\000\374\012"-
#285402	REDUCE cov: 146 ft: 1406 corp: 343/6199b lim: 1716 exec/s: 142701 rss: 133Mb L: 17/239 MS: 3 ShuffleBytes-ChangeByte-EraseBytes-
#293263	REDUCE cov: 146 ft: 1406 corp: 343/6198b lim: 1786 exec/s: 146631 rss: 133Mb L: 20/239 MS: 1 EraseBytes-
#293424	REDUCE cov: 146 ft: 1406 corp: 343/6197b lim: 1786 exec/s: 146712 rss: 133Mb L: 17/239 MS: 1 EraseBytes-
#293675	REDUCE cov: 146 ft: 1406 corp: 343/6196b lim: 1786 exec/s: 146837 rss: 133Mb L: 19/239 MS: 1 EraseBytes-
#296066	REDUCE cov: 146 ft: 1406 corp: 343/6195b lim: 1806 exec/s: 148033 rss: 133Mb L: 17/239 MS: 1 EraseBytes-
#296872	REDUCE cov: 146 ft: 1406 corp: 343/6194b lim: 1806 exec/s: 148436 rss: 133Mb L: 16/239 MS: 1 EraseBytes-
#297588	REDUCE cov: 146 ft: 1406 corp: 343/6192b lim: 1806 exec/s: 148794 rss: 133Mb L: 16/239 MS: 1 EraseBytes-
#300360	REDUCE cov: 146 ft: 1407 corp: 344/6211b lim: 1826 exec/s: 150180 rss: 133Mb L: 19/239 MS: 2 ShuffleBytes-CMP- DE: "\377\377\377~"-
#300861	NEW    cov: 146 ft: 1408 corp: 345/6230b lim: 1826 exec/s: 150430 rss: 133Mb L: 19/239 MS: 1 ChangeBit-
#301907	REDUCE cov: 147 ft: 1414 corp: 346/6250b lim: 1836 exec/s: 150953 rss: 133Mb L: 20/239 MS: 1 ChangeASCIIInt-
#302718	REDUCE cov: 147 ft: 1414 corp: 346/6249b lim: 1836 exec/s: 151359 rss: 133Mb L: 19/239 MS: 1 EraseBytes-
#303604	REDUCE cov: 147 ft: 1414 corp: 346/6247b lim: 1836 exec/s: 151802 rss: 133Mb L: 17/239 MS: 1 EraseBytes-
#305171	REDUCE cov: 147 ft: 1414 corp: 346/6245b lim: 1846 exec/s: 152585 rss: 133Mb L: 19/239 MS: 2 ShuffleBytes-EraseBytes-
#310107	REDUCE cov: 147 ft: 1414 corp: 346/6244b lim: 1886 exec/s: 155053 rss: 133Mb L: 18/239 MS: 1 EraseBytes-
#310758	NEW    cov: 148 ft: 1417 corp: 347/6260b lim: 1886 exec/s: 155379 rss: 133Mb L: 16/239 MS: 1 ChangeBit-
#312814	REDUCE cov: 148 ft: 1417 corp: 347/6258b lim: 1906 exec/s: 156407 rss: 133Mb L: 21/239 MS: 1 EraseBytes-
#313745	REDUCE cov: 148 ft: 1417 corp: 347/6255b lim: 1906 exec/s: 156872 rss: 133Mb L: 16/239 MS: 1 EraseBytes-
#320222	REDUCE cov: 148 ft: 1417 corp: 347/6254b lim: 1966 exec/s: 160111 rss: 133Mb L: 16/239 MS: 2 ChangeBit-EraseBytes-
#329183	REDUCE cov: 148 ft: 1418 corp: 348/6272b lim: 2046 exec/s: 164591 rss: 133Mb L: 18/239 MS: 1 ChangeBit-
#331122	REDUCE cov: 148 ft: 1418 corp: 348/6271b lim: 2056 exec/s: 165561 rss: 133Mb L: 16/239 MS: 4 ChangeBit-ShuffleBytes-ChangeBit-EraseBytes-
#333543	REDUCE cov: 148 ft: 1418 corp: 348/6269b lim: 2078 exec/s: 166771 rss: 133Mb L: 17/239 MS: 1 EraseBytes-
=================================================================
==39==ERROR: AddressSanitizer: global-buffer-overflow on address 0x0000007a829c at pc 0x000000597539 bp 0x7fff1682b010 sp 0x7fff1682b008
READ of size 4 at 0x0000007a829c thread T0
SCARINESS: 17 (4-byte-read-global-buffer-overflow)
    #0 0x597538 in areNeighborCells /src/h3-4-0-0/src/h3lib/lib/directedEdge.c:86:17
    #1 0x57c0b0 in LLVMFuzzerTestOneInput /src/fuzzer.c:24:22
    #2 0x44ff73 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #3 0x44f75a in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:514:3
    #4 0x450e29 in fuzzer::Fuzzer::MutateAndTestOne() /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:757:19
    #5 0x451af5 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile> >&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:895:5
    #6 0x4360c1 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:1112:6
    #7 0x46a312 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #8 0x7fa530424082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/libc-start.c:308:16
    #9 0x4212cd in _start

0x0000007a829c is located 36 bytes to the left of global variable '__const.areNeighborCells.neighborSetCounterclockwise' defined in '/src/h3-4-0-0/src/h3lib/lib/directedEdge.c' (0x7a82c0) of size 28
0x0000007a829c is located 0 bytes to the right of global variable '__const.areNeighborCells.neighborSetClockwise' defined in '/src/h3-4-0-0/src/h3lib/lib/directedEdge.c' (0x7a8280) of size 28
SUMMARY: AddressSanitizer: global-buffer-overflow (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x597538)
Shadow bytes around the buggy address:
  0x0000800ed000: 00 00 00 00 f9 f9 f9 f9 00 00 00 00 00 00 00 00
  0x0000800ed010: 00 00 00 00 00 00 00 00 f9 f9 f9 f9 00 00 00 00
  0x0000800ed020: 00 00 00 00 00 00 00 00 00 00 00 00 f9 f9 f9 f9
  0x0000800ed030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800ed040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0000800ed050: 00 00 00[04]f9 f9 f9 f9 00 00 00 04 f9 f9 f9 f9
  0x0000800ed060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800ed070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800ed080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 07 f9
  0x0000800ed090: f9 f9 f9 f9 00 00 00 00 00 02 f9 f9 f9 f9 f9 f9
  0x0000800ed0a0: 00 00 00 00 00 06 f9 f9 f9 f9 f9 f9 00 05 f9 f9
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
==39==ABORTING
MS: 1 ChangeBit-; base unit: afbe6cd2292b982c3a5093cdb55cf9d58c7b4958
0xa,0x0,0x40,0xa,0x2e,0x0,0x43,0xa,0xa,0x0,0x40,0xa,0x2a,0x0,0x43,0xa,
\012\000@\012.\000C\012\012\000@\012*\000C\012
artifact_prefix='/fuzz_set/workspace/bot/inputs/fuzzer-testcases/'; Test unit written to /fuzz_set/workspace/bot/inputs/fuzzer-testcases/crash-3586994e989fc4e3a1d9e4bd3c81f99e5226c081
Base64: CgBACi4AQwoKAEAKKgBDCg==
stat::number_of_executed_units: 334794
stat::average_exec_per_sec:     167397
stat::new_units_added:          555
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              133
INFO: exiting: 77 time: 5s


+----------------------------------------Release Build Unsymbolized Stacktrace (diff)----------------------------------------+

READ of size 4 at 0x0000007a829c thread T0
SCARINESS: 17 (4-byte-read-global-buffer-overflow)
    #0 0x597538  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x597538)
    #1 0x57c0b0  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x57c0b0)
    #2 0x44ff73  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44ff73)
    #3 0x44f75a  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x44f75a)
    #4 0x450e29  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x450e29)
    #5 0x451af5  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x451af5)
    #6 0x4360c1  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x4360c1)
    #7 0x46a312  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x46a312)
    #8 0x7fa530424082  (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #9 0x4212cd  (/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer+0x4212cd)

```

## build command
```
#!/bin/bash
mkdir fuzz-build
cd fuzz-build
cmake -DCMAKE_VERBOSE_MAKEFILE=ON -DBUILD_BENCHMARKS=OFF -DBUILD_FILTERS=OFF -DBUILD_FUZZERS=OFF -DBUILD_GENERATORS=OFF -DBUILD_TESTING=OFF -DENABLE_COVERAGE=OFF -DENABLE_DOCS=OFF  -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_COMPILER=$CC ../
make V=1 || true

$CC $CFLAGS $LIB_FUZZING_ENGINE $SRC/fuzzer.c -Wl,--whole-archive $SRC/h3-4-0-0/fuzz-build/lib/libh3.a -Wl,--allow-multiple-definition -I$SRC/h3-4-0-0/fuzz-build$SRC/h3lib/include -I$SRC/h3-4-0-0$SRC/apps/applib/include -I$SRC/h3-4-0-0$SRC/h3lib/include  -o $OUT/fuzzer
```

## Fuzz instruction
```
[Environment] ASAN_OPTIONS=alloc_dealloc_mismatch=0:allocator_may_return_null=1:allocator_release_to_os_interval_ms=500:allow_user_segv_handler=0:check_malloc_usable_size=0:detect_leaks=1:detect_odr_violation=0:detect_stack_use_after_return=1:exitcode=77:fast_unwind_on_fatal=0:handle_abort=2:handle_segv=2:handle_sigbus=2:handle_sigfpe=2:handle_sigill=2:max_uar_stack_size_log=16:print_scariness=1:print_summary=1:print_suppressions=0:quarantine_size_mb=64:strict_memcmp=1:symbolize=0:use_sigaltstack=1
```

```
["/fuzz_set/workspace/bot/builds/libfuzzer_asan_linux_test-project/custom/fuzzer","-timeout=25","-rss_limit_mb=2560","-use_value_profile=1","-fork=2","-artifact_prefix=/fuzz_set/workspace/bot/inputs/fuzzer-testcases/","-max_total_time=5600","-print_final_stats=1","/fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/new","/fuzz_set/workspace/bot/inputs/fuzzer-testcases-disk/temp-12/mutations","/fuzz_set/workspace/bot/inputs/data-bundles/fuzzer"]
```



