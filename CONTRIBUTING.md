# Contributing

Contributions that improve reproducibility, defensive coverage, portability,
or the mission builder are welcome. Review [SPEC.md](SPEC.md) and
[AGENTS.md](AGENTS.md) before changing code; they define the ABI, io_uring
layouts, assembly constraints, and acceptance criteria.

## Development setup

On Debian or Ubuntu:

```bash
sudo apt install gcc make nasm python3-pytest python3-yaml
make
python3 -m pytest builder/tests/ -q
make demo
make -C testing check
```

The root validation and EDR matrix intentionally do not run in CI. Run them
only in a disposable, authorized lab described by the testing documentation.

## Pull requests

- Keep each change focused and explain the security or reproducibility reason.
- Add tests for builder behavior and regression fixes.
- Do not commit generated binaries, generated headers, received data, logs,
  credentials, or captures containing private system information.
- Document the minimum kernel required by every new opcode. The builder must
  reject a `requires_kernel` value below the mission's effective minimum.
- Generate null-sensitive delivery artifacts with `--encode xor` and verify
  that the resulting binary contains no null bytes.
- State which checks were run and which root- or product-dependent checks were
  not available.

## Research evidence

Evidence involving EDR products must identify the exact product version,
kernel, configuration, ruleset, and test topology. Separate live-observed
results from architectural expectations. Do not generalize one product or
configuration to all EDRs.

## Security reports

Follow [SECURITY.md](SECURITY.md) for private vulnerability reporting. Never
include third-party data or test systems without authorization.
