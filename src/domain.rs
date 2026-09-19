// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which build a definition belongs to, read from its path.
//!
//! Resolving a name alone can cross builds: a chain that runs alpha -> x86
//! -> sparc, or a kernel call site landing on a `tools/` copy of the name.
//! Where a definition lives answers both, without knowing the
//! configuration:
//!
//! * **program** -- which build produces this code. The kernel image, the
//!   userspace programs under `tools/`, and the host tools a build runs are
//!   separate programs that share nothing.
//! * **architecture** -- which variant within one program. Generic code is
//!   reachable from every architecture; an architecture's own code is not
//!   reachable from another.
//!
//! The two are not the same kind of fact, and this module does not pretend
//! they are. **Architecture is a path rule**: an `arch` component names the
//! one that follows it, which also reads `tools/perf/arch/x86`.
//! **Program is a table**, because the Makefiles do not respect directory
//! boundaries: `samples/` is half kernel modules and half userspace
//! programs, `scripts/dtc/libfdt` is compiled into the kernel by
//! `lib/fdt_ro.c`, and every `tools` directory nested under another is a
//! host program.
//!
//! What this cannot see, stated so it is not discovered later:
//!
//! * Architecture-specific code outside `arch/` -- `drivers/platform/x86`
//!   and friends -- reads as generic. That over-approximates: a sparc caller
//!   can still reach it. Safe direction, but it caps what filtering claims.
//! * Rust's architecture gating is `#[cfg(CONFIG_X86)]`, invisible to a path.
//! * On a tree that is not Linux nothing matches, everything is generic
//!   kernel, and a filter built on this becomes a no-op rather than deleting
//!   candidates.
//! * Paths are repo-relative, as the index stores them.

use std::sync::atomic::{AtomicUsize, Ordering};

/// The build a file is compiled into.
///
/// `Tools` is one value rather than one per binary, and `Host` likewise:
/// finer granularity can only find more cross-program edges, never fewer, so
/// the coarse split is a floor rather than an estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Program {
    /// The kernel image and its modules.
    Kernel,
    /// Userspace programs under `tools/`, built against libc.
    Tools,
    /// Programs the build runs on the build machine: host tools, the
    /// userspace half of `samples/`, `rust/macros`, `certs/extract-cert.c`.
    Host,
    /// Not code.
    Documentation,
}

/// The architectures Linux has, as directories under `arch/`.
///
/// A closed list, so an unrecognised component cannot become a domain: a
/// typo, `arch/Kconfig`, or another tree's layout all read as generic, which
/// is the safe direction. A newly added architecture would too, so misses
/// are counted rather than silent -- see [`unknown_arch_components`].
const ARCHITECTURES: [&str; 21] = [
    "alpha",
    "arc",
    "arm",
    "arm64",
    "csky",
    "hexagon",
    "loongarch",
    "m68k",
    "microblaze",
    "mips",
    "nios2",
    "openrisc",
    "parisc",
    "powerpc",
    "riscv",
    "s390",
    "sh",
    "sparc",
    "um",
    "x86",
    "xtensa",
];

/// The userspace half of `samples/`, from the `subdir-` lines of
/// `samples/Makefile`. The rest is `obj-`, which is kernel modules.
const SAMPLES_USERSPACE: [&str; 13] = [
    "auxdisplay",
    "binderfs",
    "check-exec",
    "cgroup",
    "hidraw",
    "landlock",
    "pidfd",
    "seccomp",
    "timers",
    "uhid",
    "vfs",
    "watchdog",
    "watch_queue",
];

static UNKNOWN_ARCH: AtomicUsize = AtomicUsize::new(0);

/// How many paths named an `arch` directory this module does not know.
///
/// Zero on Linux. A non-zero count on a Linux tree means [`ARCHITECTURES`]
/// is behind the tree, which otherwise shows up only as filtering that
/// quietly stopped working for one architecture.
pub fn unknown_arch_components() -> usize {
    UNKNOWN_ARCH.load(Ordering::Relaxed)
}

/// Where a definition sits. `arch: None` is code with no architecture, which
/// every architecture of the same program can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Domain {
    pub program: Program,
    pub arch: Option<&'static str>,
}

impl Domain {
    pub const fn kernel_generic() -> Self {
        Domain {
            program: Program::Kernel,
            arch: None,
        }
    }

    /// Whether this definition's code can call `callee`'s.
    ///
    /// Directional on purpose: `arch/um` is hosted on another architecture,
    /// and a caller with no architecture is unconstrained rather than
    /// generic-only.
    pub fn can_call(self, callee: Domain) -> bool {
        Context::In(self).admits(callee)
    }
}

/// What a search is constrained to, which is not the same thing as where a
/// definition lives.
///
/// `Any` is a query that has not pinned an architecture; `In(d)` is a walk
/// that entered from `d`. Keeping this distinct from [`Domain`] is what
/// stops the two arguments of an asymmetric relation being swapped, and
/// gives a renderer a way to tell "generic definition" from "unpinned
/// query", which are the same `None` otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    Any,
    In(Domain),
}

impl Context {
    pub fn admits(self, candidate: Domain) -> bool {
        let Context::In(here) = self else {
            return true;
        };
        if here.program != candidate.program {
            return false;
        }
        match (here.arch, candidate.arch) {
            (_, None) => true,
            (None, Some(_)) => true,
            (Some(a), Some(b)) => a == b,
        }
    }
}

/// What can be said about two definitions of one name both existing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coexistence {
    /// Proved apart: different architectures of one program.
    CannotCoexist,
    /// Different builds entirely. Both are real; neither excludes the other,
    /// and neither should resolve to the other.
    DifferentBuilds,
    /// Nothing proved. Same architecture may still mean different builds --
    /// m68k has three `pte_present` and sparc two -- and an architecture's
    /// definition overrides `include/asm-generic` rather than joining it, so
    /// this is never a claim that both are present.
    Unproved,
}

/// What can be said about two definitions coexisting. Never claims they do.
pub fn coexistence(left: Domain, right: Domain) -> Coexistence {
    if left.program != right.program {
        return Coexistence::DifferentBuilds;
    }
    match (left.arch, right.arch) {
        (Some(a), Some(b)) if a != b => Coexistence::CannotCoexist,
        _ => Coexistence::Unproved,
    }
}

fn components(path: &str) -> Vec<&str> {
    path.split('/').filter(|part| !part.is_empty()).collect()
}

/// The program a path belongs to. A table, not a rule: see the module doc.
fn program_of(parts: &[&str]) -> Program {
    match parts.first() {
        Some(&"Documentation") => return Program::Documentation,
        // scripts/dtc/libfdt is kernel code: lib/fdt_ro.c is two lines, the
        // second of which includes scripts/dtc/libfdt/fdt_ro.c.
        Some(&"scripts") => {
            return match parts.get(1) {
                Some(&"dtc") if parts.get(2) == Some(&"libfdt") => Program::Kernel,
                _ => Program::Host,
            }
        }
        Some(&"samples") => {
            return match parts.get(1) {
                // samples/bpf builds *_user.c for the host and *_kern.c as
                // BPF objects; neither is in the kernel image.
                Some(&"bpf") => Program::Host,
                Some(dir) if SAMPLES_USERSPACE.contains(dir) => Program::Host,
                _ => Program::Kernel,
            };
        }
        Some(&"tools") => return Program::Tools,
        // A proc-macro crate, compiled for the build machine.
        Some(&"rust") if parts.get(1) == Some(&"macros") => return Program::Host,
        Some(&"certs") if parts.get(1) == Some(&"extract-cert.c") => return Program::Host,
        _ => {}
    }
    // Every `tools` directory nested under another is a host program, which
    // is the twelve under arch/ and the reason choose_definition needed to
    // demote them.
    if parts.iter().skip(1).any(|part| *part == "tools") {
        return Program::Host;
    }
    Program::Kernel
}

/// The architecture a path names, if this module knows it.
///
/// An `arch` component names the architecture after it, wherever it appears,
/// so `tools/perf/arch/x86` and `tools/objtool/arch/powerpc` read the same
/// way as `arch/x86`. `arch/<host>/um/**` is um's own code -- Kbuild pulls
/// it in with `core-y += $(HOST_DIR)/um/` -- so it is um, not the host.
fn arch_of(parts: &[&str]) -> Option<&'static str> {
    let index = parts.iter().position(|part| *part == "arch")?;
    let named = parts.get(index + 1)?;
    let known = ARCHITECTURES.iter().copied().find(|arch| arch == named);
    if known.is_none() {
        UNKNOWN_ARCH.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    if parts.get(index + 2) == Some(&"um") {
        return Some("um");
    }
    known
}

/// The domain of a file, read from its path alone.
///
/// ```
/// use semcode::domain::{domain_of, Program};
/// let d = domain_of("arch/x86/kernel/setup.c");
/// assert_eq!(d.program, Program::Kernel);
/// assert_eq!(d.arch, Some("x86"));
/// ```
pub fn domain_of(path: &str) -> Domain {
    let parts = components(path);
    let program = program_of(&parts);
    // A host tool's architecture is the build machine's, not the target's,
    // so arch/x86/tools/insn_decoder_test.c must not carry x86 into a filter
    // about target code.
    let arch = match program {
        Program::Kernel | Program::Tools => arch_of(&parts),
        Program::Host | Program::Documentation => None,
    };
    Domain { program, arch }
}

/// Whether a path belongs to a program other than the kernel image.
///
/// The question `choose_definition` has asked since it had to stop ranking
/// `arch/x86/tools/insn_decoder_test.c` above a real definition. Answered
/// here so the tree holds one taxonomy rather than two.
pub fn path_is_other_program(file_path: &str) -> bool {
    domain_of(file_path).program != Program::Kernel
}

#[cfg(test)]
mod tests {
    use super::*;

    // Witnesses are paths taken from the index at Linux 50d05c7c76c9, not
    // from memory. The previous version of this file passed every test while
    // being wrong, because the test and the code had chosen the same witness.

    #[test]
    fn arch_comes_from_the_path() {
        assert_eq!(domain_of("arch/x86/kernel/setup.c").arch, Some("x86"));
        assert_eq!(domain_of("arch/sparc/mm/init_64.c").arch, Some("sparc"));
        assert_eq!(
            domain_of("arch/arm/mach-omap2/board-generic.c").arch,
            Some("arm")
        );
        // 26 definitions of pte_present live in headers like this one.
        assert_eq!(
            domain_of("arch/x86/include/asm/pgtable.h").arch,
            Some("x86")
        );
    }

    #[test]
    fn an_arch_component_is_found_wherever_it_sits() {
        // tools/perf/arch has 14 architectures and tools/arch has 17;
        // requiring position two read the larger body of code as generic.
        assert_eq!(
            domain_of("tools/perf/arch/x86/util/evsel.c").arch,
            Some("x86")
        );
        assert_eq!(
            domain_of("tools/objtool/arch/powerpc/decode.c").arch,
            Some("powerpc")
        );
        assert_eq!(
            domain_of("tools/arch/x86/lib/memcpy_64.S").arch,
            Some("x86")
        );
    }

    #[test]
    fn an_unknown_arch_directory_is_generic_and_counted() {
        let before = unknown_arch_components();
        // arch/Kconfig is not an architecture, and a future one this list
        // has not learned must not become a domain either.
        assert_eq!(domain_of("arch/Kconfig").arch, None);
        assert_eq!(domain_of("arch/newarch/kernel/setup.c").arch, None);
        assert!(unknown_arch_components() > before);
    }

    #[test]
    fn um_glue_under_a_host_tree_is_um() {
        // arch/um/Makefile:42, `core-y += $(HOST_DIR)/um/`. 305 definitions
        // live here, and 93 of the 97 um edges that reach outside arch/um
        // land in them -- which is why um needs no inheritance rule.
        assert_eq!(domain_of("arch/x86/um/syscalls_64.c").arch, Some("um"));
        assert_eq!(domain_of("arch/x86/um/asm/processor.h").arch, Some("um"));
        // Native x86 code in the same tree is still x86.
        assert_eq!(domain_of("arch/x86/kernel/process.c").arch, Some("x86"));
        assert_eq!(domain_of("arch/um/kernel/process.c").arch, Some("um"));
    }

    #[test]
    fn um_does_not_reach_x86_nor_x86_um() {
        // With um glue read as um, the inheritance relation is gone: these
        // are plain different architectures, and 187 impossible candidate
        // admissions on the native side go with it.
        let um = domain_of("arch/um/kernel/process.c");
        let x86 = domain_of("arch/x86/kernel/process.c");
        assert!(!um.can_call(x86));
        assert!(!x86.can_call(um));
        assert!(um.can_call(domain_of("arch/x86/um/syscalls_64.c")));
    }

    #[test]
    fn generic_kernel_code_has_no_architecture() {
        assert_eq!(domain_of("mm/memory.c"), Domain::kernel_generic());
        assert_eq!(
            domain_of("include/linux/dev_printk.h"),
            Domain::kernel_generic()
        );
        // usr/initramfs_data.S is linked into the image.
        assert_eq!(domain_of("usr/gen_init_cpio.c").program, Program::Kernel);
    }

    #[test]
    fn samples_is_half_userspace() {
        // samples/Makefile: 31 obj- lines against 13 subdir- lines.
        assert_eq!(
            domain_of("samples/kprobes/kprobe_example.c").program,
            Program::Kernel
        );
        assert_eq!(
            domain_of("samples/livepatch/livepatch-sample.c").program,
            Program::Kernel
        );
        assert_eq!(
            domain_of("samples/seccomp/bpf-direct.c").program,
            Program::Host
        );
        assert_eq!(
            domain_of("samples/landlock/sandboxer.c").program,
            Program::Host
        );
        // samples/bpf builds *_user.c for the host and *_kern.c as BPF
        // objects: neither is the kernel image, which is what
        // tests/ambiguous_single_answer.rs asserts too.
        assert_eq!(
            domain_of("samples/bpf/sockex1_kern.c").program,
            Program::Host
        );
    }

    #[test]
    fn scripts_is_host_except_the_part_the_kernel_compiles() {
        assert_eq!(domain_of("scripts/kconfig/conf.c").program, Program::Host);
        assert_eq!(domain_of("scripts/mod/modpost.c").program, Program::Host);
        // lib/fdt_ro.c is two lines: an include of linux/libfdt_env.h and an
        // include of this file.
        assert_eq!(
            domain_of("scripts/dtc/libfdt/fdt_ro.c").program,
            Program::Kernel
        );
    }

    #[test]
    fn a_nested_tools_directory_is_a_host_program() {
        // The definition that made path_is_other_program necessary.
        let d = domain_of("arch/x86/tools/insn_decoder_test.c");
        assert_eq!(d.program, Program::Host);
        // And its architecture is the build machine's, not x86, so it cannot
        // be preferred by an x86 caller's filter.
        assert_eq!(d.arch, None);
    }

    #[test]
    fn host_crates_and_tools_are_host() {
        assert_eq!(domain_of("rust/macros/module.rs").program, Program::Host);
        assert_eq!(domain_of("certs/extract-cert.c").program, Program::Host);
        // rust/kernel is the kernel itself.
        assert_eq!(domain_of("rust/kernel/print.rs").program, Program::Kernel);
    }

    #[test]
    fn tools_is_another_program_and_documentation_is_neither() {
        assert_eq!(
            domain_of("tools/virtio/linux/kernel.h").program,
            Program::Tools
        );
        assert_eq!(
            domain_of("tools/perf/builtin-stat.c").program,
            Program::Tools
        );
        assert_eq!(
            domain_of("Documentation/core-api/index.c").program,
            Program::Documentation
        );
    }

    #[test]
    fn this_is_the_taxonomy_choose_definition_already_used() {
        // tests/ambiguous_single_answer.rs asserts exactly these.
        assert!(path_is_other_program("arch/x86/tools/insn_decoder_test.c"));
        assert!(path_is_other_program("tools/lib/bpf/relo_core.c"));
        assert!(path_is_other_program("samples/bpf/sockex1_kern.c"));
        assert!(path_is_other_program("Documentation/tools/whatever.c"));
        assert!(!path_is_other_program("include/linux/printk.h"));
        assert!(!path_is_other_program("mm/memory.c"));
    }

    #[test]
    fn generic_is_reachable_from_every_architecture() {
        // x86 do_page_fault calling generic handle_mm_fault in mm/memory.c.
        assert!(domain_of("arch/x86/mm/fault.c").can_call(domain_of("mm/memory.c")));
        assert!(domain_of("arch/sparc/mm/fault_64.c").can_call(domain_of("mm/memory.c")));
    }

    #[test]
    fn one_architecture_does_not_reach_another() {
        let x86 = domain_of("arch/x86/kernel/setup.c");
        let sparc = domain_of("arch/sparc/mm/init_64.c");
        assert!(!x86.can_call(sparc));
        assert!(!sparc.can_call(x86));
        assert!(x86.can_call(domain_of("arch/x86/include/asm/pgtable.h")));
    }

    #[test]
    fn programs_are_disjoint_in_both_directions() {
        // 33,052 kernel edges reach for dev_err; with the kernel's own
        // definition unparsed, the copy in tools/virtio/linux/kernel.h is
        // the only candidate left.
        let kernel = domain_of("drivers/net/ethernet/intel/ice/ice_main.c");
        let tools = domain_of("tools/virtio/linux/kernel.h");
        assert!(!kernel.can_call(tools));
        assert!(!tools.can_call(kernel));
        // 249 kernel edges resolve to a `volatile` macro in samples/bpf.
        assert!(!kernel.can_call(domain_of("samples/bpf/asm_goto_workaround.h")));
    }

    #[test]
    fn an_unpinned_query_admits_everything_a_generic_caller_admits_its_program() {
        // Generic __schedule reaching one of 19 switch_to definitions is a
        // fan-out, not a resolution: the caller's program constrains, its
        // absent architecture does not.
        let generic = domain_of("kernel/sched/core.c");
        assert!(generic.can_call(domain_of("arch/x86/include/asm/switch_to.h")));
        assert!(generic.can_call(domain_of("arch/arm64/include/asm/switch_to.h")));
        assert!(!generic.can_call(domain_of("tools/perf/builtin-stat.c")));
        // An unpinned query is a different thing and admits both programs.
        assert!(Context::Any.admits(domain_of("tools/perf/builtin-stat.c")));
        assert!(Context::Any.admits(domain_of("arch/x86/kernel/setup.c")));
    }

    #[test]
    fn coexistence_proves_apartness_and_never_togetherness() {
        let x86 = domain_of("arch/x86/include/asm/pgtable.h");
        let arm = domain_of("arch/arm64/include/asm/pgtable.h");
        assert_eq!(coexistence(x86, arm), Coexistence::CannotCoexist);
        // m68k defines pte_present three times -- mcf, motorola, sun3 -- all
        // arch m68k and never in one build, so same-architecture is not a
        // claim that both are present.
        let mcf = domain_of("arch/m68k/include/asm/mcf_pgtable.h");
        let motorola = domain_of("arch/m68k/include/asm/motorola_pgtable.h");
        assert_eq!(coexistence(mcf, motorola), Coexistence::Unproved);
        // 665 names are defined in both asm-generic and an arch tree, where
        // the arch definition overrides rather than joins.
        assert_eq!(
            coexistence(x86, domain_of("include/asm-generic/bitops/fls.h")),
            Coexistence::Unproved
        );
        // Two programs are unrelated, not exclusive.
        assert_eq!(
            coexistence(domain_of("lib/rbtree.c"), domain_of("tools/lib/rbtree.c")),
            Coexistence::DifferentBuilds
        );
    }

    #[test]
    fn odd_paths_do_not_panic_or_lie() {
        assert_eq!(domain_of(""), Domain::kernel_generic());
        assert_eq!(domain_of("arch"), Domain::kernel_generic());
        assert_eq!(domain_of("arch/"), Domain::kernel_generic());
        // The index holds repo-relative paths only; an absolute one would be
        // read by its components, which is wrong but cannot occur.
        assert_eq!(domain_of("Makefile"), Domain::kernel_generic());
    }
}
