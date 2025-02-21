# Fuzzing helloworld

## TODO
* LibAFL - qemu_launcher
  * Nearly done
  * coredumps everywhere!
  * SIGSEGV causes the fuzzer to crash. See bookmark!
* Parallel fuzzing: https://crates.io/crates/afl_runner
* LibAFL - Make an afl-cc like compiler wrapper and a forkserver based fuzzer?
* Start reading through AFL++ and LibAFL repos
* Make target harder to crash. Each class of vuln should be hard to get to to compare efficacy and throughput of each option. Also make one dependent on a checksum (for CMPLOG)
* 

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>