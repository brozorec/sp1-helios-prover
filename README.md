# SP1 Helios Prover
This project serves as an exploration playground for the creation of an Ethereum ZK Light Client with [Helios](https://github.com/a16z/helios) by using [Succinct's SP1 zkVM](https://github.com/succinctlabs/sp1).

**Helios**

Helios is a fully trustless, efficient, and portable Ethereum light client written in Rust.
Helios converts an untrusted centralized RPC endpoint into a safe unmanipulable local RPC for its users. It syncs in seconds, requires no storage, and is lightweight enough to run on mobile devices.

**SP1**

SP1 is a performant, 100% open-source, contributor-friendly zero-knowledge virtual machine (zkVM) that can prove the execution of arbitrary Rust (or any LLVM-compiled language) programs. SP1 democratizes access to ZKPs by allowing developers to use programmable truth with popular programming languages.

### Goal
As both tools are Rust programs, the goal is to combine them and generate verifiable proofs for the operations done by the light client.

Initial list of tasks:
1. Prove finality (done)
2. Prove the next sync committee
3. Prove sync committee signature

### Quick Start
Before, follow the SP1 [installation guide](https://succinctlabs.github.io/sp1/getting-started/install.html).

terminal 1:
```
❯ cd program
❯ cargo prove build
```
terminal 2:
```
❯ cd script
❯ cargo run --release
```
