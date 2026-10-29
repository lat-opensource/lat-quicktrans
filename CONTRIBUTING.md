# Contributing to Quicktrans

By submitting a contribution, you agree to license it under the MIT License
in the repository's `LICENSE` file. You must have the right to submit the
contribution under those terms.

Do not copy code from another project unless its license permits inclusion in
Quicktrans and all required copyright and license notices are preserved. Mark
third-party or differently licensed files with an accurate SPDX license
identifier and update `THIRD_PARTY_NOTICES.md` when needed.

Before submitting a change, run:

```sh
meson setup build
ninja -C build
ninja -C build test
```
