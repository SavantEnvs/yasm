# NULL-pointer dereference in `yasm_intnum_get_int()`

- **Target:** `fuzz_gas`
- **Reproducer:** `repro.s` (a mutated copy of one of the seed corpus's own
  `.set`/`.byte` GAS-syntax tests; the fuzzer corrupted the right-hand side
  of one `.set y, <expr>` line into a handful of non-ASCII bytes)
- **Crash site:** `libyasm/intnum.c:747`, inside `yasm_intnum_get_int()`:
  ```c
  long
  yasm_intnum_get_int(const yasm_intnum *intn)
  {
      switch (intn->type) {   /* <-- crashes here when intn == NULL */
  ```
- **Sanitizer:** UndefinedBehaviorSanitizer (`-fsanitize=null`) -- "member
  access within null pointer of type 'const yasm_intnum'".

## Cause

The reproducer redefines symbol `y` via `.set y, <corrupted-expression>`
where the right-hand side fails to evaluate to a normal integer expression
(the fuzzer replaced it with raw non-ASCII bytes), then references `y` from
a `.byte y` directive. Some path from the GAS parser's `.byte`/symbol-value
resolution down to `yasm_intnum_get_int()` does not check the intnum pointer
it was handed for NULL before dereferencing `intn->type` -- i.e. whatever
computes/looks up the value for `y` for that `.byte` directive can return
NULL (e.g. on a still-unresolved or malformed `.set` right-hand side) and
that NULL is not checked by this call site before use.

This is a distinct defect from the `array-bounds`/`shift-base`/
`nonnull-attribute` UBSan false positives relaxed in `mayhem/build.sh`
(struct-hack expression terms, the embedded BitVector library's mask
computation, and the re2c scanner buffer's `memcpy(dst, NULL, 0)` refill
idiom, respectively, none of which are genuine bugs) -- this one is a real,
unchecked NULL pointer used for a normal struct member access.

## Impact

Denial of service: a `.set`-redefined symbol with an expression that fails
to resolve to a normal value, later used in a `.byte` (and plausibly other
data-emitting) directive, crashes the assembler on attacker/third-party GAS
source. As with the `fuzz_nasm` finding in this cohort, no evidence of
further exploitability (write primitive) was found within the scope of this
integration pass -- this is a read of a NULL pointer, not a controlled
out-of-bounds write.

## Suggested upstream fix

Either (a) have the caller that resolves `y`'s value for the `.byte`
directive check for a NULL/failed intnum and raise a normal parser error
instead of passing NULL onward, or (b) defensively guard
`yasm_intnum_get_int()` (and its sibling accessors in `libyasm/intnum.c`)
against a NULL `intn` and return a sentinel / call `yasm_internal_error()`
with a clear message instead of dereferencing. The exact upstream call site
that first produces the NULL intnum for this construct was not further
isolated given the scope of this integration pass.

## Reproduce

```sh
/mayhem/fuzz_gas-standalone mayhem/fuzz_gas/known-findings/nullderef-intnum-get-int/repro.s
```
