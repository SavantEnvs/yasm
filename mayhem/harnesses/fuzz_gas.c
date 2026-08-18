/* mayhem/harnesses/fuzz_gas.c -- fuzz yasm's GAS-syntax front end
 * (modules/parsers/gas: gas-parse.c / gas-parse-intel.c, a DIFFERENT parser
 * front end than NASM syntax) via libyasm's module API. See fuzz_common.c
 * for the harness design.
 */
#include <stddef.h>
#include <stdint.h>

#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return yasm_fuzz_run(data, size, "gas");
}
