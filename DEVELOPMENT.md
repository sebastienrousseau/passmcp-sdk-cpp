<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Development

Local equivalents of every CI gate for `passmcp-sdk-cpp` (C++20 / CMake 3.24+).

## Gates

| Gate | Command |
|---|---|
| Full check suite | `make check` |
| Unit & conformance tests | `make test` |
| Linter / static analysis | `make lint` |
| REUSE / SPDX compliance | `reuse lint` |
| Ecosystem manifest check | `make family` |
| Lockstep version check | `make lockstep` |
| Runnable example | `make example` |
