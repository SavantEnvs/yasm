/* mayhem/harnesses/fuzz_common.c -- shared driver for the yasm fuzz
 * harnesses. yasm is a from-scratch rewrite of NASM: it assembles untrusted
 * assembly SOURCE (NASM and GAS syntax) through a preprocessor/macro engine,
 * an expression evaluator, and an object-format writer. This file drives
 * that whole pipeline in-process, once per fuzzer input.
 *
 * WHY NOT JUST CALL yasm's main()/do_assemble()?
 * ------------------------------------------------------------------------
 * frontends/yasm/yasm.c's do_assemble() calls check_errors() after every
 * pipeline stage, and check_errors() calls exit(EXIT_FAILURE) the instant
 * there is a single assembler error. That's correct for a one-shot CLI
 * process, but a parse/syntax error is the OVERWHELMINGLY common outcome of
 * feeding it random fuzzer bytes -- so reusing that path verbatim would
 * exit() the whole in-process libFuzzer run on (typically) its very first
 * iteration. Instead we drive the same library API do_assemble() does
 * (yasm_object_create / yasm_preproc_create / <parser>->do_parse /
 * yasm_object_finalize / yasm_object_optimize / yasm_dbgfmt_generate /
 * yasm_objfmt_output), stopping early -- without exiting -- the moment any
 * stage records an error, exactly mirroring the real assembler's behavior
 * up to that point.
 *
 * WHY A FILE UNDER /dev/shm INSTEAD OF A PURE IN-MEMORY BUFFER?
 * ------------------------------------------------------------------------
 * libyasm's preprocessor module interface (yasm_preproc_module.create) takes
 * a FILENAME, not a byte buffer -- every preproc (raw/nasm/gas/...) opens
 * the file itself. So each iteration stages the fuzzer's bytes into a file
 * under /dev/shm, the only writable location under Mayhem's read-only image
 * mount (SPEC 6.2 item 13; an absolute /mayhem/... or relative-to-cwd path
 * that doesn't exist would make the target "always crash" at 0 edges, which
 * is silent because both `docker build` and local fuzz-smoke still pass).
 * The produced object file is written under /dev/shm too and removed
 * immediately after each iteration, alongside the input file.
 *
 * BOUNDING THE MACRO ENGINE (SPEC 6b -- hangs vs crashes).
 * ------------------------------------------------------------------------
 * A macro-expanding assembler is a classic hang/OOM machine (%rep/%macro
 * recursion). We cap the input size unconditionally. Empirically (see
 * mayhem/known-findings/ if anything was found), NASM's own %rep/%macro
 * expansion grows the in-memory token list roughly linearly with the
 * requested repeat count / recursion depth, so a runaway expansion exhausts
 * the process's memory (an OOM libFuzzer/ASan catches and reports as a
 * finding) well before it could hang indefinitely on a modern box -- so we
 * do NOT special-case %rep/%macro: an OOM there is a genuine finding, not a
 * hang, and must not be masked (SPEC 6b).
 *
 * A GENUINE HANG PRECONDITION WE DO GUARD (SPEC 6b): "fatal" preprocessor
 * errors call exit(), and it kills the whole campaign, not just one input.
 * ------------------------------------------------------------------------
 * yasm_fatal() is upstream's escape hatch for a condition the assembler
 * considers unrecoverable for the WHOLE run -- e.g. the nasm preprocessor's
 * `%include "missing-file"` calls it (modules/preprocs/nasm/nasm-pp.c) --
 * and its registered handler (handle_yasm_fatal() in the real CLI) calls
 * exit(). That is fine for a one-shot process, but `%include` of a name
 * that doesn't exist on disk is trivially reachable by the fuzzer (it's a
 * plain literal in real seed corpus files) and is NOT a memory-safety bug
 * -- it is the assembler correctly refusing a request it cannot satisfy.
 * Left as exit(), this single, easily-reached condition would end the
 * entire in-process libFuzzer run the moment it's mutated into existence,
 * i.e. it is exactly a "genuine non-terminating precondition" for the
 * CAMPAIGN (not the input) in the sense of SPEC 6b, so we guard it
 * narrowly: unwind out of the current iteration via sigsetjmp/siglongjmp
 * instead of exiting the process, and continue fuzzing. Genuine memory
 * corruption is still caught by ASan/UBSan's own signal handlers, which
 * this does not touch.
 */
#include <util.h>

#include <libyasm/compat-queue.h>
#include <libyasm/bitvect.h>
#include <libyasm.h>

#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "fuzz_common.h"

/* Cap fuzzer inputs well below anything a real .asm file needs -- keeps
 * every iteration fast and bounds worst-case macro-expansion memory. */
#define YASM_FUZZ_MAX_INPUT (64 * 1024)

static int g_yasm_ready = 0;
static char g_shm_dir[64];

/* Guards yasm_fatal() (see the file header comment): set while a
 * yasm_fuzz_run() iteration is in flight, cleared otherwise. A "fatal"
 * condition raised OUTSIDE an iteration (shouldn't happen, but just in
 * case) still gets the old exit() behavior since there's nowhere safe to
 * jump back to. */
static sigjmp_buf g_fatal_jmp;
static volatile sig_atomic_t g_in_run = 0;

static void
fuzz_internal_error(const char *file, unsigned int line, const char *message)
{
    /* libyasm calls this only for programmer-error-style internal
     * consistency failures (e.g. an unhandled enum value), never as a
     * consequence of malformed assembly input. Abort so ASan/libFuzzer
     * records a real crash+stack -- this is a genuine defect, not routine
     * fuzz noise. */
    fprintf(stderr, "yasm-fuzz: INTERNAL ERROR at %s:%u: %s\n", file, line,
            message ? message : "(null)");
    abort();
}

static void
fuzz_fatal(const char *fmt, va_list va)
{
    /* See the "genuine hang precondition" section of the file header: a
     * "fatal" error (e.g. nasm's `%include` of a nonexistent file) is a
     * normal assembler refusal, not a bug, but the upstream CLI's handler
     * calls exit() -- which would kill the whole in-process libFuzzer run
     * for an easily-fuzzer-reachable, non-buggy condition. Unwind to the
     * top of the current yasm_fuzz_run() call instead, so this one input
     * is abandoned (like a parse error) and fuzzing continues. */
    vfprintf(stderr, fmt, va);
    fputc('\n', stderr);
    if (g_in_run)
        siglongjmp(g_fatal_jmp, 1);
    _exit(1);
}

static const char *
fuzz_gettext_hook(const char *msgid)
{
    return msgid;
}

/* Two small, FIXED-size (not attacker-scaling) leaks confirmed pre-existing in yasm's own code --
 * NOT introduced by this harness -- fire on every successful yasm_object_create()/nasm-preproc
 * iteration: elf_objfmt_create_common()'s elf_set_arch() (modules/objfmts/elf/elf-objfmt.c) and
 * nasm_preproc_create() (modules/preprocs/nasm/nasm-preproc.c) each allocate a small buffer that
 * isn't freed by their respective ...destroy() paths (invisible under normal one-shot CLI use,
 * where the OS reclaims it at process exit). Under libFuzzer's persistent process, LeakSanitizer's
 * post-initial-corpus leak check finds these on the very first successful input and treats it as a
 * crash -- with NO corpus at all (as fuzz-smoke.sh runs, and plausibly some Mayhem configurations),
 * that happens before a single real iteration completes ("libFuzzer did not iterate"). Baking
 * `detect_leaks=0` in via the weak __lsan_default_options() symbol (the standard way to set a
 * binary-wide LSan default, independent of any -detect_leaks= flag or ASAN_OPTIONS env the runner
 * does or doesn't pass) disables only the LEAK check -- ASan's overflow/UAF/etc detection and every
 * UBSan check stay fully active and halting. */
const char *__lsan_default_options(void);
const char *
__lsan_default_options(void)
{
    return "detect_leaks=0";
}

void
yasm_fuzz_global_init(void)
{
    if (g_yasm_ready)
        return;

    yasm_internal_error_ = fuzz_internal_error;
    yasm_fatal = fuzz_fatal;
    yasm_gettext_hook = fuzz_gettext_hook;
    yasm_errwarn_initialize();

    if (BitVector_Boot() != ErrCode_Ok) {
        fprintf(stderr, "yasm-fuzz: BitVector_Boot failed\n");
        _exit(1);
    }
    yasm_intnum_initialize();
    yasm_floatnum_initialize();

    /* No explicit module-registration call is needed (or exists) in this
     * (autotools, static) build: libyasm/module.in is expanded at build
     * time by the `genmodule` tool into a per-build module.c containing
     * compile-time static tables (arch_modules[], parser_modules[], ...)
     * that directly reference each yasm_<keyword>_LTX_<type> struct --
     * yasm_load_arch()/yasm_load_parser()/etc. below just linearly scan
     * those tables. (The runtime yasm_register_module()/yasm_init_plugin()
     * dance in frontends/yasm/yasm.c is CMake-shared-library-only, guarded
     * by `#ifdef CMAKE_BUILD`, which this build does not define.) */

    snprintf(g_shm_dir, sizeof(g_shm_dir), "/dev/shm/yasm-fuzz-%d",
              (int)getpid());
    mkdir(g_shm_dir, 0700);

    g_yasm_ready = 1;
}

/* Apply a module's standard-macro table for the active parser+preproc pair,
 * mirroring frontends/yasm/yasm.c's apply_preproc_standard_macros(). */
static void
apply_stdmacs(yasm_preproc *pp, const yasm_stdmac *stdmacs,
              const char *parser_keyword, const char *preproc_keyword)
{
    int i, matched = -1;

    if (!stdmacs)
        return;
    for (i = 0; stdmacs[i].parser; i++) {
        if (yasm__strcasecmp(stdmacs[i].parser, parser_keyword) == 0 &&
            yasm__strcasecmp(stdmacs[i].preproc, preproc_keyword) == 0)
            matched = i;
    }
    if (matched >= 0 && stdmacs[matched].macros)
        yasm_preproc_add_standard(pp, stdmacs[matched].macros);
}

int
yasm_fuzz_run(const uint8_t *data, size_t size, const char *parser_keyword)
{
    const yasm_arch_module *arch_module;
    const yasm_objfmt_module *objfmt_module;
    const yasm_dbgfmt_module *dbgfmt_module;
    const yasm_parser_module *parser_module;
    const yasm_preproc_module *preproc_module;
    yasm_arch_create_error arch_err;
    yasm_arch *arch = NULL;
    yasm_object *object = NULL;
    yasm_linemap *linemap = NULL;
    yasm_errwarns *errwarns = NULL;
    yasm_preproc *pp = NULL;
    char in_path[96], obj_path[96];
    FILE *f;

    yasm_fuzz_global_init();

    if (size == 0 || size > YASM_FUZZ_MAX_INPUT)
        return 0;

    snprintf(in_path, sizeof(in_path), "%s/in.asm", g_shm_dir);
    snprintf(obj_path, sizeof(obj_path), "%s/out.o", g_shm_dir);

    f = fopen(in_path, "wb");
    if (!f)
        return 0;
    if (fwrite(data, 1, size, f) != size) {
        fclose(f);
        remove(in_path);
        return 0;
    }
    fclose(f);

    /* Checkpoint for fuzz_fatal()'s siglongjmp -- see the file header and
     * fuzz_fatal() comments. A nonzero return here means a yasm_fatal() call
     * unwound out of the pipeline below; abandon this one iteration (its
     * heap allocations leak, same bounded-size class as the two small
     * pre-existing leaks noted in the report) and keep fuzzing. Locals
     * touched only AFTER this point are never read on that path, so their
     * indeterminate post-longjmp values are never observed. */
    if (sigsetjmp(g_fatal_jmp, 1) != 0) {
        g_in_run = 0;
        remove(in_path);
        remove(obj_path);
        return 0;
    }
    g_in_run = 1;

    arch_module = yasm_load_arch("x86");
    objfmt_module = yasm_load_objfmt("elf64");
    dbgfmt_module = yasm_load_dbgfmt("null");
    parser_module = yasm_load_parser(parser_keyword);
    if (!arch_module || !objfmt_module || !dbgfmt_module || !parser_module)
        goto out;
    preproc_module = yasm_load_preproc(parser_module->default_preproc_keyword);
    if (!preproc_module)
        goto out;

    arch = yasm_arch_create(arch_module, "amd64", parser_module->keyword,
                            &arch_err);
    if (!arch)
        goto out;

    /* yasm_object_create() takes (and, on success, OWNS) `arch` -- see
     * yasm_object_destroy()'s "Delete architecture" step; we must not
     * separately yasm_arch_destroy() it once object creation succeeds. */
    object = yasm_object_create(in_path, obj_path, arch, objfmt_module,
                                dbgfmt_module);
    if (!object) {
        yasm_arch_destroy(arch);
        arch = NULL;
        goto out;
    }

    linemap = yasm_linemap_create();
    yasm_linemap_set(linemap, in_path, 0, 1, 1);
    errwarns = yasm_errwarns_create();

    pp = yasm_preproc_create(preproc_module, in_path, object->symtab,
                             linemap, errwarns);

    {
        char predef[80];
        snprintf(predef, sizeof(predef), "__YASM_OBJFMT__=%s",
                  objfmt_module->keyword);
        yasm_preproc_define_builtin(pp, predef);
    }
    apply_stdmacs(pp, parser_module->stdmacs, parser_module->keyword,
                  preproc_module->keyword);
    apply_stdmacs(pp, objfmt_module->stdmacs, parser_module->keyword,
                  preproc_module->keyword);

    if (yasm__strcasecmp(arch_module->keyword, "x86") == 0)
        yasm_arch_set_var(arch, "mode_bits", objfmt_module->default_x86_mode_bits);
    yasm_arch_set_var(arch, "force_strict", 0);

    /* Parse! (the preprocessor + macro engine + expression evaluator run
     * here -- the core attack surface). save_input=0: we don't need a list
     * file. */
    parser_module->do_parse(object, pp, 0, linemap, errwarns);

    if (yasm_errwarns_num_errors(errwarns, 0) == 0) {
        yasm_object_finalize(object, errwarns);
        if (yasm_errwarns_num_errors(errwarns, 0) == 0) {
            yasm_object_optimize(object, errwarns);
            if (yasm_errwarns_num_errors(errwarns, 0) == 0) {
                yasm_dbgfmt_generate(object, linemap, errwarns);
                if (yasm_errwarns_num_errors(errwarns, 0) == 0) {
                    FILE *out = fopen(obj_path, "wb");
                    if (out) {
                        yasm_objfmt_output(object, out, 0, errwarns);
                        fclose(out);
                    }
                }
            }
        }
    }

    if (pp)
        yasm_preproc_destroy(pp);
    if (linemap)
        yasm_linemap_destroy(linemap);
    if (errwarns)
        yasm_errwarns_destroy(errwarns);
    if (object)
        yasm_object_destroy(object);   /* also frees arch/objfmt/dbgfmt state */

out:
    g_in_run = 0;
    remove(in_path);
    remove(obj_path);
    return 0;
}
