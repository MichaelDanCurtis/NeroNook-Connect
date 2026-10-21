# Nero Connect · local two-Mac pilot

Independent macOS 14+ app and signed admission service using the owner's existing
free `neronook-connect-test` Supabase project. It does not depend on NeroNook,
Nero Voice, Fuego or a checkout of their source. It has no remote action endpoint.
This slice shares one explicitly edited sample note, not calendars or files.

## Try it on two Macs

1. Open **Nero Connect** on the first Mac. Enter the email approved for your
   Supabase organization, choose **Send sign-in link**, and open that email on
   this same Mac. Choose **Set up this Mac** after signing in.
2. Copy `dist/Nero-Connect-0.1.1-local.zip` to the other Mac using your normal
   transfer method. Unzip and open the app. Sign in independently with the same
   email, opening its new sign-in email on that second Mac.
3. With both apps ready, choose **Add my other Mac** on the trusted first Mac.
   Copy its complete `NERO1.` code into the second Mac and request pairing.
   The invitation lasts five minutes; creating it after both sign-ins avoids
   spending the pairing window waiting for email.
4. Compare the short code on both screens. On the first Mac choose **Codes match
   · Approve this Mac**. The second Mac cannot read shared notes before approval.
5. Share an authored test note from one Mac and watch it arrive on the other.
   Pause sync on one Mac, share another edit from the other, then resume. A
   queued local edit made against an old revision appears as a conflict, with
   both versions available and an explicit choice of which to keep.
6. Close one app, edit on the other, then reopen it. Confirm its sign-in and
   pairing restore and that the new note arrives. A queued edit must retain its
   original message ID/bytes through retries; a second acceptance is not a
   second shared update.

These are owner acceptance steps, not a claim they have been completed on two
physical Macs. Automated native-client tests are separately described in the
host's dated evidence report. No personal meeting data is needed for this test.

This is a **local Developer ID-signed development build**, not a notarized public
release. Another Mac may ask the owner to trust it. No notarization upload or
public distribution was performed. The universal binary declares macOS 14 as
its minimum for both Apple Silicon and Intel; older-OS runtime behavior still
requires the actual target Mac test.

## Sign-in and pairing behavior

- Official Supabase Auth 2.55.4 uses PKCE and the exact native callback
  `cafe.nero.connect://auth-callback`. Each Mac obtains its own session. A copied
  application bundle contains a public publishable key, never a user session,
  private device key or service-role key.
- The Free default mailer is limited to permitted organization addresses and
  low send rates. No custom SMTP, paid mail service or email template changes
  were configured. Broader tester sign-in requires a separately configured
  mailer/provider; this build does not promise that any arbitrary Gmail works.
- Login alone cannot enroll a second Mac. A one-use 256-bit invitation and an
  existing device's signed approval pin both full device identities. First
  enrollment, requests, membership/session checks and mutations serialize on
  the owner's service record. New or revoked devices have no direct table API.
- Sample notes use CryptoKit's RFC 9180 HPKE with X25519/HKDF-SHA256/
  ChaCha20-Poly1305. Ed25519 signatures bind owners, devices, revisions and exact
  ciphertext. The relay sees device names/IDs, routing, timestamps and sizes;
  it receives no clear note text.
- Private keys and Auth data use this app's non-syncing local Keychain namespace.
  The cache/outbox is encrypted and written atomically with cursor/state.
  **The classic Mac Keychain did not retain the requested `ThisDeviceOnly`
  accessibility attribute in an isolated OS probe.** Do not infer hardware-backed,
  non-migratable or lock-screen protection from that flag. No automatic key or
  account-session transfer is implemented. Stronger Data Protection Keychain
  packaging/entitlements remain a release-security task.
- Removing a pairing blocks future service access and keeps a tombstone. It
  cannot erase already saved notes. The removed Mac can explicitly create new
  keys and request fresh approval. Old encrypted caches/retired keys remain
  local; account-key loss/recovery is not implemented.
- An expired, unapproved request releases its slot. Old expired invitations
  cannot delete a new live pending request for the same identity. Approved and
  revoked identities are not removed by timeout cleanup.

## Runtime limits

Two registered live Macs per account, 4 KiB note text, one queued local edit,
1,000 accepted message envelopes, 100 lifetime invitations, 100 inbox rows/page,
1 MiB local encrypted cache, two-minute signed-request window and a bounded
nonce history. These are prototype backpressure limits, not silent eviction.

The running app currently polls at four-second intervals; offline requests time
out and retry. This favors a short interactive test and has not been qualified
as an inexpensive always-on production schedule. Realtime hints, adaptive
backoff, retention/compaction and sustained energy/usage qualification remain.
Closing the last window quits the pilot, retaining encrypted local state and
its own Keychain sign-in. It does not install a login item or background daemon.
Pause cancels automatic client polling; an already accepted server write is
not undone by pausing. Windows/iOS adapters and Nook presentation are future
work against the documented portable wire contract.

## Build and checks

```sh
swift build
swift test
bash scripts/package.sh
```

`Resources/Service.json` is deliberately untracked local public-client
configuration (`url`, `publishableKey`). It must contain only this named project
and a modern publishable key. Never put an administrator key there. Package
resolution and Node fixtures have committed lockfiles; build scripts do not
fetch credentials or change signing permissions.

The service directory contains versioned migrations and the Edge handler. Its
Node harness creates disposable synthetic owners without sending mail, passes
their random credentials only through a local pipe to native Auth clients,
and removes those users/records afterward. It is opt-in, binds the exact test
project, and must not be run against a production account. Human mail delivery,
actual desktop UI and two physical Macs require their own acceptance.

To repeat that opt-in hosted fixture on the owner's authorized test service:
build `ConnectProbe`, install the service directory's pinned dependencies with
`npm ci --ignore-scripts`, then set `CONNECT_PROBE_PATH` to this checkout's built
probe and run `node service/test-fixture.mjs`. Optional `CONNECT_REPORT_DIR`
selects the local evidence directory; it defaults to this checkout's `reports`.
This requires the owner's normal authenticated Supabase CLI. No administrator
credentials are bundled in the app or read from another product.

No independent cryptographic audit, forward secrecy across stored history,
automatic recovery, production denial-of-service assurance or other-platform
qualification is claimed. Native host/SDK/plugin installations remain unchanged;
the owner's local-only release policy and 0.35.0 public release floor remain.
