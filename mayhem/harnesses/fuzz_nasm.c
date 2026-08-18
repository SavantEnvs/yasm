/* mayhem/harnesses/fuzz_nasm.c -- fuzz yasm's NASM-syntax front end
 * (modules/parsers/nasm: nasm-parse.c + the nasm preprocessor's macro
 * engine in modules/preprocs/nasm/nasm-pp.c) via libyasm's module API. See
 * fuzz_common.c for the harness design.
 */
#include <stddef.h>
#include <stdint.h>

#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return yasm_fuzz_run(data, size, "nasm");
}
