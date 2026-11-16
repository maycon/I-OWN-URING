# Security Policy

## Scope

I-OWN-URING is an authorized-security-research project. Reports about defects
that could unexpectedly affect users of the builder, test harness, or supplied
artifacts are welcome. The documented ability to evade monitoring that relies
only on `sys_enter` is the research subject, not a vulnerability in this
repository.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that has not been coordinated.
Use GitHub's **Report a vulnerability** form in the repository's Security tab
to submit a private advisory. Include:

- the affected commit and file;
- the security boundary and concrete impact;
- minimal reproduction steps using dummy data; and
- any proposed remediation.

For ordinary bugs, documentation corrections, and reproducibility problems,
open a regular GitHub issue.

## Supported versions

Until tagged releases exist, only the current `main` branch is supported. Once
a release is published, this file will identify the supported release line.

## Responsible use

Run the shellcode, injector, listeners, and EDR demonstrations only on systems
you own or have explicit written permission to test. Reports must not include
credentials, production data, or evidence collected from third-party systems.
