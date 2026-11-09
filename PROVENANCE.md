# Provenance and verification

Expected SSH signing fingerprint: `SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU`.

Before a future public release, compare this pin with a trusted channel. Download the chosen archive plus SHA256SUMS.txt, SHA256SUMS.txt.sig and SIGNING-PUBLIC-KEY.pub into one directory. From a trusted checkout, run:

```sh
python tools/verify_downloads.py --directory DOWNLOAD_DIR --work NEW_VERIFY_DIR --trusted-fingerprint SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU --archive EXACT_ARCHIVE_NAME
```

The verifier checks a single canonical pinned key, SSH file-namespace signature and selected archive bytes; attacker keys/comments, tampered archives and noncanonical inputs have independent regressions. A key shipped beside bytes is not itself a trust root.

Signed commits/tags/checksums show provenance under that key, not OS code signing, independent authorship, formal correctness, reproducible builds, a security/SLSA certification, exchange conformance or financial results. BUILD-MANIFEST identifies exact source/tree, build host and local-candidate status. SPDX checksums describe actual raw signed upstream archive bytes, while normalized NuGet contentHash describes restore identity. Build attestations, if the authorized GitHub pipeline succeeds, add source/build provenance only.

Local candidates are not public releases. Existing unrelated projects and private/shared assets are outside this provenance claim.
