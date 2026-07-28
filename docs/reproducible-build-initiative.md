# QHUB — Reproducible Build Initiative (FUTURE follow-up)

**Status:** DEFERRED — documented scope only. Not implemented in this phase.

## Why this exists

The current assurance model is **deployed-image integrity**, not source-to-artifact
reproducibility. The build-info diagnostic and the Agent Run fail-closed checks
compare the deployment-injected identity (`QHUB_BUILD_*`) against the independent
on-image identity (`QHUB_IMAGE_*`) across **source commit, artifact hash, and
lockfile hash**, and record a non-secret build-environment fingerprint. They
prove: *the running Fly image matches the exact recorded build artifact, source
commit, lockfile, and build environment used for that release.*

They do **not** claim that an independent rebuild produces a byte-identical
artifact. It was verified that two clean builds of the same source on the same
machine are **byte-identical in executable code** but differ only in
toolchain-generated content-hash chunk *filenames* (Vite/Rollup emits
non-deterministic content-hash names build-to-build; the differing bytes are the
embedded cross-chunk filename references). A second Vite build may therefore
produce a different artifact hash — this is expected under the current model.

## Scope (later, as a separate initiative)

- deterministic Vite/Rollup chunk generation (stable content-hash algorithm or
  pinned chunk naming) so identical source → identical artifact hash;
- container-pinned build environment (fixed base image, Node, pnpm);
- deterministic bundle/module ordering;
- stable toolchain versions;
- cache/versioning (long-term-caching) impact assessment for renamed assets;
- source-map determinism;
- cross-platform (Windows/Linux) verification.

## Explicitly out of scope now

Do not change chunk naming, switch to unhashed filenames, normalize executable
bundle content to force matching hashes, or exclude executable chunks / cross-chunk
references from the artifact manifest. The artifact hash remains a hash of the
exact executable artifact created in that build.
