# Windows native remediation candidate

Starts from public Sparrow `bdca675348dc701eff4d5c29eb1f2fcf1780a934`.
The signing/coordinator Java source remains unchanged. This local candidate
replaces five Windows DLLs and protects extraction against overwriting them
with old dependency resources. Physical qualification and independent
source/notice acceptance remain pending. Jade support is not enabled.

`windows-x64-manifest.json` records hashes, resource paths and selected build
outputs. Full actual native sources, patches, configuration, Cargo lock/vendor
sources, toolchain logs, licenses and static-USB relinking files are delivered
in `windows-native-corresponding-source-2026-10-08.zip` in the separate reviewer
materials. See its `NATIVE-SOURCE-AND-REPLACEMENT.md` for build/replacement steps.
These sources correspond to the new DLLs; they do not authenticate the old
modified binaries. Verify the delivery packet checksum before using it.

Selected sources:

- ZBar 0.23.92: `aac86d5f08d64ab4c3da78188eb622fa3cb07182`.
- GNU libiconv/libcharset 1.17: upstream archive SHA-256
  `8f74213b56238c85a50a5329f77e06198771e70dd9a739779f4c02f65d971313`.
- libusb 1.0.27: `d52e355daa09f17ce64819122cb067b8a2ee0d4b`;
  libusb4java JNI: `2df684b0bb5495276858dcc6c945b0ca2e13a6c5`.
- secp256k1/JNI: `6dd724b72bb2d47de514eb92e96c6ae6d26ae160`.
- BWT JNI 0.2.4: `6f945d4d58418fbb36cea03940b7613940b619a0`;
  Core-v23 BWT: `b7ffc6ad032c5e1e04207baaa250a4465c8d6fd0`;
  ntapi 0.3.6 has the recorded packed-pointer compatibility patch.

No broad upstream sync, firmware change or protocol change is included.
