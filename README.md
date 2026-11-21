# @c9up/orbit-secure-store

Strings kept encrypted on the phone, optionally behind a biometric check.

```ts
import { biometricStatus, deleteItem, getItem, setItem } from "@c9up/orbit-secure-store";

await setItem("session", token);
const token = await getItem("session"); // null when there is none
await deleteItem("session");

if ((await biometricStatus()).enrolled) {
  await setItem("db-key", key, { requireAuthentication: true });
  const key = await getItem("db-key", { prompt: { title: "Unlock" } });
}
```

- **Phone (Android)**: each value is AES-256-GCM ciphertext under a key that
  never leaves the Android Keystore, in the app's no-backup directory (a
  backup restored elsewhere would carry ciphertext without its key). A value
  set with `requireAuthentication` has a key of its own that only a strong
  biometric check unlocks, each time, and that enrolling a new fingerprint
  invalidates — the value is then gone (`E_ORBIT_SECURE_STORE_INVALIDATED`).
  A Kotlin TurboModule, added by React Native's autolinking to an app built by
  `ream android:*`. Nothing logs a value.
- **Browser and server**: no equivalent — a browser's storage is readable by
  every script on the page — so every call rejects with
  `E_ORBIT_SECURE_STORE_UNAVAILABLE`, and `biometricStatus()` answers
  `{ hardware: false, enrolled: false }`.
- iOS (the Keychain) is still to come.

Keys are 1 to 128 of `A-Z a-z 0-9 . _ -`.

With orbit's server connection, an API token survives an app restart:

```ts
const server = connectServer("https://app.example", {
  tokenStore: {
    get: () => getItem("session"),
    set: (token) => (token === null ? deleteItem("session") : setItem("session", token)),
  },
});
await server.restore(); // authorized again if a token was kept
```

## Errors

Every failure is an `OrbitSecureStoreError` with a `code`:

| Code | Cause |
|---|---|
| `E_ORBIT_SECURE_STORE_UNAVAILABLE` | No secure store: the browser, the server, an app built without the module. |
| `E_ORBIT_SECURE_STORE_INVALID_KEY` | A key that is not 1 to 128 of `A-Z a-z 0-9 . _ -`. |
| `E_ORBIT_SECURE_STORE_NO_BIOMETRICS` | `requireAuthentication` on a phone with no strong biometric enrolled. |
| `E_ORBIT_SECURE_STORE_AUTH_CANCELLED` | The user dismissed the biometric prompt. |
| `E_ORBIT_SECURE_STORE_AUTH_FAILED` | The check failed for good: too many attempts, a lockout, a hardware error. |
| `E_ORBIT_SECURE_STORE_INVALIDATED` | The key behind the value is gone (a new biometric enrolled, the app's data restored): so is the value. |
| `E_ORBIT_SECURE_STORE_FAILED` | Anything else the platform reported; never carries the value. |

## License

MIT
