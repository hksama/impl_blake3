# Cryptography Skill

The implementation prioritizes correctness.

Rules

Never

- change constants
- simplify rotations
- replace wrapping arithmetic
- alter endian conversions
- rewrite bit operations without proof

Every optimization must preserve bit-exact output.

When reviewing

Verify

- flags
- counter
- block length
- IV
- permutations
- message schedule
- parent compression
- tree reduction

Always compare against

- official specification
- official BLAKE3 implementation

Treat every constant as specification-derived.

Performance is secondary.

Correctness is mandatory.