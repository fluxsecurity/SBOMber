# T7 — Packaging Matrix

## Result

Candidate B has substantially simpler cross-platform packaging.

## Candidate A

Candidate A:

- built successfully for Linux/amd64 with `CGO_ENABLED=1`;
- failed with `CGO_ENABLED=0`;
- requires platform-specific C cross-compilers for other targets;
- produced a dynamically linked Linux binary;
- produced a binary of approximately 5.3 MB;
- requires glibc 2.34 or later for the tested Linux build.

The failed cross-builds do not prove that Candidate A cannot support those
platforms. They show that separate native C toolchains are required.

## Candidate B

Candidate B:

- built for Linux, macOS and Windows;
- built for amd64 and arm64 targets;
- passed with both `CGO_ENABLED=0` and `CGO_ENABLED=1`;
- produced statically linked Linux binaries;
- required only the standard Go cross-compilation toolchain.

The default build was 27,545,762 bytes.

Using the confirmed selective grammar tags:

- `grammar_subset_javascript`;
- `grammar_subset_typescript`;
- `grammar_subset_tsx`;

reduced the Linux/amd64 binary to 9,277,602 bytes.

This is a reduction of approximately 66.3%.

The selective binary passed extraction against all 13 fixtures with zero
differences from the hand-labelled expected results.

## Decision relevance

Candidate B clearly wins the packaging criterion. It provides static,
CGO-free, cross-platform binaries without external C toolchains.

Candidate A produces a smaller binary, but adds CGO, native toolchain and
glibc compatibility requirements.

Packaging therefore favours Candidate B, while parser correctness and
robustness must still be considered separately in the final decision.
