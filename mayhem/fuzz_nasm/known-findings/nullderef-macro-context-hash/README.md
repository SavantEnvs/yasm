# NULL-pointer dereference in the NASM preprocessor's macro-context hash lookup

- **Target:** `fuzz_nasm`
- **Reproducer:** `repro.asm` (159 bytes, minimized only by the fuzzer's own corpus
  minimization -- not hand-minimized further)
- **Crash site:** `modules/preprocs/nasm/nasm-pp.c:1114`, inside `hash(char *s)`:
  ```c
  static int
  hash(char *s)
  {
      ...
      while (*s)          /* <-- crashes here when s == NULL */
      {
          h += multipliers[i] * (unsigned char) (toupper(*s));
          ...
  ```
- **Sanitizer:** UndefinedBehaviorSanitizer (`-fsanitize=null`, part of the default
  `-fsanitize=undefined` set) -- "load of null pointer of type 'char'".

## Cause

`hash()` is called with a macro-context `name` field taken directly from the
preprocessor's internal `%rep`/`%push`/`%pop` context-stack bookkeeping, e.g.
`mmacros[hash(searching.name)]` (nasm-pp.c:2201) during `%rep`/`%endrep`
matching. The reproducer nests a `%push`/local-context (`%$x`) block inside a
`%rep 8` body, with a literal NUL byte embedded in the middle of an `%assign`
line, immediately before a same-line, case-varied `%eNdrep` (matches
`%endrep` case-insensitively) and `%pop`. That combination leaves the
context-stack entry's `name` pointer NULL by the time a later lookup calls
`hash()` on it -- i.e. some path through the `%rep`/context-stack state
machine fails to validate that a context has a `name` before hashing it,
instead of the "always non-NULL after construction" invariant the rest of
`nasm-pp.c` otherwise assumes.

This looks adjacent to, but distinct from, the pre-existing (and separately
observed during the same fuzzing run) UBSan `array-bounds` report in
`libyasm/expr.c:1141` -- that one is a **false positive**: `yasm_expr` uses
the classic pre-C99 "struct hack" (`yasm_expr__item terms[2]` declared as a
fixed size-2 array but allocated with extra trailing elements for `ADD`/`MUL`/
`OR`/`AND`/`XOR` expressions with more than two terms, per the type's own
doc comment) which UBSan's static array-bounds check cannot see through. That
one and a similarly pervasive `left shift of negative value` in
`libyasm/bitvect.c:404` (`~0L << mask`, also a benign, extremely common
pattern in this embedded BitVector library) are both intentionally relaxed
via `-fno-sanitize=array-bounds,shift-base` in `mayhem/build.sh` -- see the
comment there. **This NULL-deref is not in that category**: it is a genuine
use of an invalid (NULL) pointer, not a sanitizer false positive.

## Impact

Denial of service: any caller of `yasm`/`libyasm` that assembles
attacker-controlled NASM source (the exact scenario `fuzz_nasm` exercises)
can be crashed via a crafted `%rep`/`%push`/`%macro` sequence. No evidence of
further exploitability was found (no out-of-bounds write; a NULL read is not
directly generally controllable), but assembling arbitrary/third-party
`.asm` sources (e.g., in a build pipeline) is a real usage pattern for yasm,
so this is a genuine availability bug, not merely a fuzzing artifact.

## Suggested upstream fix

In `hash()` (nasm-pp.c:1101), guard against a NULL `s`:
```c
static int
hash(char *s)
{
    unsigned int h = 0, i = 0;
    if (!s)
        return 0;   /* or another sentinel bucket, per caller's expectations */
    ...
```
That's a safe, narrow, one-line-per-callsite-avoiding fix; the deeper root
cause (why the context-stack entry's `name` is NULL when a `%rep`/`%endrep`
pairing is unbalanced by a same-line, mixed-case `%endrep` on a line that
also contains an embedded NUL byte) was not further isolated given the scope
of this integration pass.

## Reproduce

```sh
/mayhem/fuzz_nasm-standalone mayhem/fuzz_nasm/known-findings/nullderef-macro-context-hash/repro.asm
```
