# LibAFL notes


/// C  Clone
/// CM Command Manager
/// ED Emulator Driver
/// EM Event Manager (Event Firer + Event Restarter)
/// ES Executor State
/// H  Harness function
/// HT (Executor) Hooks Tuple
/// I Input + Unpin
/// OF (Observer?) Feedback
/// OT Observers Tuple
/// S  Has Solutions
/// SP Shmem Provider
/// Z  Fuzzer
/// 
/// Z, , S, Z>
/// 
/// 
/// run_target
/// GenericInProcessForkExecutor - fork, shmem
/// StatefulGenericInProcessForkExecutor - fork, shmem
/// 
/// GenericInProcessExecutor
/// 
/// 
/// feature: fork
/// QemuForkExecutor
/// 

InProcessExecutor

ForkserverExecutor

InprocessForkExecutor


QemuExecutor
    inner: EmulatorInProcessExecutor
    == StatefulInProcessExecutor
Instantiated with an `Emulator` (see below)


QemuForkExecutor
    inner: QemuInProcessForkExecutor
    == StatefulInProcessForkExecutor

libafl_qemu/src/qemu/mod.rs:
Qemu     // The wrapper around QEMU
         // Still quite low-level, e.g. read_mem(), write_mem(), restore_state()
         // For higher-level use `Emulator`

libafl_qemu/src/emu/mod.rs:
Emulator // convenient abstractions for Qemu 

libafl_qemu/libafl_qemu_sys/src/lib.rs:
This create exports C symbols for QEMU. For example:
use libafl_qemu_sys::{
    libafl_qemu_remove_breakpoint
}

Emulator // The high-level interface to `Qemu`

When our fuzzer runs...
```
let mut emulator = Emulator::empty() // returns an `EmulatorBuilder`
            .qemu_parameters(args)   // Adds args
            .modules(modules)        // etc.
            .build()?;
```

build() instantiates the Emulator, which has a Qemu::init(params) inside.
This ultimately calls libafl_qemu_init(), one of the C bindings.

Our harness, which has a reference to the Qemu instance, calls
Qemu.entry_break() which behind the scenses sets breakpoints and runs:
    self.set_breakpoint() [libafl_qemu_set_breakpoint]
    self.run() [libafl_qemu_run]
    self.remove_breakpoint() [libafl_qemu_remove_breakpoint]


qemu_cmin. Uses an InMemoryOnDiskCorpus to track the inputs that were unique? At the end, only unique ones kept.
How does it do this? Is one of its items a tuple of edges?

Cf. afl-cmin...


EdgeCoverageModule

libafl_qemu/src/modules/edges/child.rs fn_hitcount:
        emulator_modules.edges(
            Hook::Function(gen_hashed_edge_ids::<AF, ET, PF, I, S, Self, IS_CONST_MAP, MAP_SIZE>),

libafl_qemu/src/modules/edges/classic.rs fn_hitcount:
        emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, I, S, Self, IS_CONST_MAP, MAP_SIZE>),

libafl_qemu/src/modules/edges/full.rs fn_hitcount:
        emulator_modules.edges(
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, I, S, Self, IS_CONST_MAP, MAP_SIZE>),


These functions `fn_hitcount` call edges() which ultimately passes the functions to libafl_add_edge_hook() (or similar) low-level bindings. 
This happens on first_exec.

qemu_cmin uses StdEdgeCoverageChildModule
qemu_linux_kernel/process (full system) uses StdEdgeCoverageClassicModule

But the `edge` module typedefs StdEdgeCoverageModule = StdEdgeCoverageFullModule, so it's the default for most.

edge module:
/// Standard edge coverage module, adapted to most use cases
pub type StdEdgeCoverageModule = StdEdgeCoverageFullModule;
/// Standard edge coverage module builder, adapted to most use cases
pub type StdEdgeCoverageModuleBuilder = StdEdgeCoverageFullModuleBuilder;

So, gen_unique_edge_ids() is called back from QEMU, and it adds hashes of the current edgeID to a map. libafl_qemu_hook_edge_gen

Edge = (src, dst)

Gen Hook: Called by libafl_qemu_hook_edge_gen
Exec Hook: Called by libafl_qemu_hook_edge_run

There's some wrapper magic that allows C functions in QEMU to call Rust functions.


StdTMinMutationalStage - attempts to minimise corpus entries.

ObserverEqualityFactory is the observer that ensures test case is *not* interesting.

The InMemoryOnDiskCorpus is what stores a corpus on disk (and in memory). It implements the add() function of Corpus trait.

The StdState has load_file() which runs an input (it's got the fuzzer and executor, so can call fuzzer.evaluate_input), and the result determines whether it gets added as fuzzer.add_disabled_input(). It returns result Corpus or None depending.

In qemu_cmin, the MaxMapFeedback with HitcountsMapObserver is what decides whether an input is interesting or not.

## Components

Harness - The function or closure we want to test. The harness (target) really
  needs to update something, whether that's coverage data or some other piece of data.

Observer - An observation channel, e.g. StdMapObserver which will observe a map of something
  e.g. a map of the signals.
  Still a black box to me.

Feedback - Struct to rate the interestingness of an input.
  e.g. MaxMapFeedback::new(&observer) takes our observation channel and considers
  'interesting' when ...???

Objective - Struct to decide if an input is a solution (crash?) or not.
  e.g. CrashFeedback::new() = ExitKindFeedback<CrashLogic> which checks the
  exit kind of an execution, and if it was a Crash then yes. (Who sets Crash?)

State - e.g. StdState (???) takes:
  - rand
  - corpus - Initial input corpus
  - solutions - Corpus of solutions (mutations that pleased Objective)
  - feedback (above)
  - objective (above)



Fuzzer (Evaluator trait) - e.g. StdFuzzer::new() takes:
  - scheduler (above)
  - feedback (above)
  - objective (above)
  evaluate_input() for StdFuzzer:
    - exit_kind = execute_input()
        - executor.observers_mut().pre_exec_all()
        - start_timer!
        - exit_kind = executor.run_target()
            - Enter target (divider between fuzzer and harness)

Executor - e.g. InProcessExecutor::new() takes:
  - harness (see above)
  - observers (tuple_list!() of all observers, above)
  - fuzzer (above)
  - state (above)
  - manager (above)

Generator - e.g. RandPrintablesGenerator::new() can gerate random printable bytearrays.

StdState.generate_initial_inputs() - Can be used to generate initial inputs. It takes:
  - fuzzer (above)
  - executor (above)
  - generator (above)
  - Manager (above)
  - Number of cases to generate
  It just calls generator.generate() a number of times and runs fuzzer.evaluate_input() with them.