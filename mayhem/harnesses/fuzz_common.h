/* mayhem/harnesses/fuzz_common.h -- shared driver for the yasm libFuzzer
 * harnesses (fuzz_nasm.c, fuzz_gas.c). See fuzz_common.c for the design
 * rationale. Named ".h" (not picked up by yasm's own build) and only ever
 * referenced from mayhem/build.sh.
 */
#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>

/* One-time process-global setup: error handlers, BitVector/intnum/floatnum
 * tables, and static module registration (yasm_init_plugin()). Idempotent;
 * safe (and expected) to call at the top of every LLVMFuzzerTestOneInput. */
void yasm_fuzz_global_init(void);

/* Assemble `data`/`size` bytes of source through libyasm's parser named
 * `parser_keyword` ("nasm" or "gas"), using that parser's default
 * preprocessor, x86/amd64 architecture, the elf64 object format, and no
 * debug format. Always returns 0 (libFuzzer contract) -- assembler errors on
 * malformed input are the expected common case, not a harness failure.
 */
int yasm_fuzz_run(const uint8_t *data, size_t size, const char *parser_keyword);

#endif
