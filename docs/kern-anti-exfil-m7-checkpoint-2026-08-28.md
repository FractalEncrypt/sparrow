# Kern anti-exfil M7 identity checkpoint

Date: 2026-08-28

## Identity and import

- `WalletModel.KERN` is appended at ordinal 45. Existing model ordinals remain
  unchanged and are pinned by a Drongo regression test.
- The Kern importer reuses the reviewed Specter DIY parser but always replaces
  the generic parser identity with `KERN`.
- File and scanned-QR paths both default Kern to `OPTIONAL` protected signing
  and the explicit `AEXT_V1` profile.
- The importer has Kern-specific label/help text and dedicated light, dark, and
  compact logo resources.

## Explicit capability boundary

Keystores persist an `AntiExfilProfile` independently of `WalletModel` and
policy. Protected workflow selection requires an exact reviewed model/profile
pair from `AntiExfilDeviceRegistry`; model identity alone is insufficient.

The current registry is:

| Model | Profile | OPTIONAL | REQUIRED |
| --- | --- | ---: | ---: |
| SeedSigner | `AEXT_V1` | yes | yes |
| Kern | `AEXT_V1` | yes | no, pending M8 |

A SeedSigner labeled with `IN_PSBT_V1`, a generic Specter DIY, or a model with
no registered profile cannot enter the protected QR workflow merely because a
policy field was set.

## Persistence and migration

- JSON stores `antiExfilProfile` and migrates legacy supported SeedSigner
  keystores to `AEXT_V1`; other legacy models remain `NONE`.
- Database migration V12 adds a non-null string profile. It maps only legacy
  supported SeedSigner rows to `AEXT_V1` and leaves all other rows `NONE`.
- Database insert, load, and policy/profile update paths persist both values.
- Keystore copies and settings/import replacement flows preserve the profile.

## Verification

Focused Sparrow tests cover importer identity, QR metadata, exact capability
matching, JSON round trips, legacy JSON defaults, DB round trips, V12 migration,
and the existing anti-exfil policy-selection suite. Drongo separately tests
copy semantics, stable profile IDs, and the append-only model ordinal.

M7 deliberately leaves Kern `REQUIRED` unavailable. M8 physical 2 x 2
conformance is the gate for changing that registry bit.
