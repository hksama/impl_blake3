# Testing Skill

Every exported algorithm requires

1. Unit tests

2. Edge cases

3. Differential tests

4. Property tests

6. Randomized tests

7. Benchmark later

Every internal function should verify

Inputs

↓

State transition

↓

Outputs

↓

Invariants

Hash functions require

- empty input
- one byte
- block boundaries
- chunk boundaries
- multiple chunks
- large inputs
- deterministic outputs

Always compare with the official crate.

Prefer many small focused tests over large tests.

Random tests should use deterministic seeds.

No flaky tests.