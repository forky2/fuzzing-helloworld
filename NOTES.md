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

## Components - based on Baby Fuzzer

Harness - The function or closure we want to test.
  Since we prefer a generative fuzzer that gets feedbacks over one that doesn't,
  our harness really needs to update something, whether that's coverage data or
  some other piece of data.
  And it needs to do something to indicate a solution state (e.g. crash).
  In the baby_fuzzer example, an array of u8 is used in a contrived way to
  represent coverage; a "signals map".

Observer - An observation channel, e.g. StdMapObserver which will observe a map
  of something (like the the above signals map).
  Must implement: CanTrack + AsRef<O> + Named
  The observer seems to maintain a state of the result of one execution only.

Feedback - Struct to rate the interestingness of an input.
  e.g. MaxMapFeedback::new(&observer) takes our observer and considers
  an input interesting when the "observation" is simply different from all
  previous observations. e.g. previous runs yielded all 0s, but this latest run
  yielded a 1 in the map.
  The Max in the name means that in a competition between last and current, the
  larger number wins, so that means the novel `0..1..0` wins over `0..0`.
  Clearly a MinMapFeedback would not be of use in our scenario. (The fuzzer
  would never gain new interesting inputs and will only find the crash by
  brute force random luck).
  Needs to be StateInitializer + Feedback.
  Needs to have a Reducer? e.g. a MaxReducer or a MinReducer.

Objective - Struct to decide if an input is a solution (crash?) or not.
  e.g. CrashFeedback::new() = ExitKindFeedback<CrashLogic> which checks the
  exit kind of an execution, and if it was a Crash then yes. (Who sets Crash?)

State - e.g. StdState (???) takes:
  - rand - Source of (hopefully) high entropy
  - corpus - Initial input corpus
  - solutions - Corpus of solutions (mutations that pleased Objective)
  - feedback - (above)
  - objective - (above)

Monitor - struct that decides how stats/events/information are displayed to user
  Could be a complicated ncurses style frontend, or it could be a simple logger.
  In baby_fuzzer, `let mon = SimpleMonitor::new(|s| println!("{s}"));` creates
  a simple monitor that just prints out whatever it's fed.

EventManager - e.g. SimpleEventManager::new(mon).
  I'm still not sure of the point of this component. From the docs:
  Another required component is the EventManager. It handles some events such as
  the addition of a testcase to the corpus during the fuzzing process. For our
  purpose, we use the simplest one that just displays the information about
  these events to the user using a Monitor instance.
  At the most minimal, I think it needs to implement a ProgressReporter.
  For a NopFuzzer, it needs to be ProgressReporter.
  For a StdFuzzer, it needs to be ProgressReporter + EventFirer + SendExiting + EventReceiver
  And the executor (GenericInProcessExecutor) requires it to be a EventFirer + EventRestarter too.
  I know it creates its own ClientStatsManager on instantiation.
  Anyway, how is it used?
  Well, when StdState.generate_initial_inputs() is called it will...
  - fuzzer.evaluate_input()
    - I think mgr is just passed in here so its pointer can be saved before harness executes.
      This is something that the InProcess executor does.
  - call manager.fire([Some Event]), which (jesus) tells self.client_stats_manager about that thing. If it's an unhandled event it will push it onto its local vector of events.

Scheduler - e.g. QueueScheduler::new(). Apparently the scheduler defines how the
  fuzzer requests a testcase from the corpus. QueueScheduler would seem to be a
  trivial queue of items. But anyway, the Scheduler trait defines:
    - on_add() called when a testcase is added to the corpus
    - on_evaluation() when an input has been evaluated
    - next() get the next entry
    - set_current_scheduled() sets the current fuzzed corpusid.
  It gets things from state (which it is passed in all these calls) I think.

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
  It will only keep an initial random generation as an input if it is *interesting*!
  If you just want the first x random inputs regardless of interestingness, use
  generate_initial_inputs_forced().

Mutators - Before fuzzing, we need mutators. (Well we could run without any but
  it would be pretty pointless.) We use the StdScheduledMutator::new() which
  takes a tuple of structs that implement the Mutator trait (they have a
  mutate() function). These mutators are passed to the fuzzer as a stage in the
  execution loop.
  The mutator(s) receive a pointer to the input data and they get to do their
  thing on it.
  There is a NopMutator which does nothing, and is there for testing. Nice.

Finally we can call fuzzer.fuzz_loop().

## qemu_cmin

Ensure you understand this first.

SimpleRestartingEventManager:
```
///The [`SimpleRestartingEventManager`] is a combination of a
/// `restarter` and `runner`, that can be used on systems both with and without `fork` support. The
/// `restarter` will start a new process each time the child crashes or times out.
```

Shared memory is used for the edges map, but it's only really required for the
fork mode. If snapshot mode is used then it's not adding anything as everything
is in one-process anyway.

(In snapshot mode, shared memory will be used for llmp to connect different
fuzzer nodes, but that's another matter.)

cmin works by running all of a corpus through as `state.load_initial_inputs()`
so that only uniquely interesting (i.e. edge map is the hash key) inputs
are kept. It makes no attempt to reduce those test cases.

## baby_fuzzer_minimizing

The key to minimising a test case is here:

```
let minimizer = StdScheduledMutator::new(havoc_mutations());
let mut stages = tuple_list!(StdTMinMutationalStage::new(
    minimizer,
    CrashFeedback::new(),
    1 << 10,
));
```

This stage 'minimizer' is running all of the havoc_mutations repeatedly (1<<10
times).



## qemu_tmin

Need to understand reducers before undertaking.


load_input_into: extern/LibAFL/libafl/src/corpus/inmemory_ondisk.rs#L195
Called whenever a test case is mutated.

is_interesting_u8_simd_optimized: extern/LibAFL/libafl/src/feedbacks/map.rs#L610
For calculating if a coverage map change is interesting.