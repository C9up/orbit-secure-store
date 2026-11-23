/**
 * orbit-secure-store's errors, one per code: a stable
 * `E_ORBIT_SECURE_STORE_<REASON>` for a caller to branch on. A cancelled
 * biometric check is not a failed one.
 */
import { createError } from "@c9up/flare";

/** No secure store here: the browser, the server, an app built without the module. */
export const E_ORBIT_SECURE_STORE_UNAVAILABLE = createError<[string]>(
	"[orbit-secure-store] %s",
	"E_ORBIT_SECURE_STORE_UNAVAILABLE",
);

/** A key that is not 1 to 128 of `A-Z a-z 0-9 . _ -`. */
export const E_ORBIT_SECURE_STORE_INVALID_KEY = createError<[string]>(
	"[orbit-secure-store] %s",
	"E_ORBIT_SECURE_STORE_INVALID_KEY",
);

/** `requireAuthentication` on a phone with no strong biometric enrolled. */
export const E_ORBIT_SECURE_STORE_NO_BIOMETRICS = createError<[string]>(
	"[orbit-secure-store] %s",
	"E_ORBIT_SECURE_STORE_NO_BIOMETRICS",
);

/** The user dismissed the biometric prompt. */
export const E_ORBIT_SECURE_STORE_AUTH_CANCELLED = createError<[string]>(
	"[orbit-secure-store] %s",
	"E_ORBIT_SECURE_STORE_AUTH_CANCELLED",
);

/** The biometric check failed for good (too many attempts, a lockout, a hardware error). */
export const E_ORBIT_SECURE_STORE_AUTH_FAILED = createError<[string]>(
	"[orbit-secure-store] %s",
	"E_ORBIT_SECURE_STORE_AUTH_FAILED",
);

/** The key behind the value is gone (a new biometric enrolled, the app's data restored): the value with it. */
export const E_ORBIT_SECURE_STORE_INVALIDATED = createError<[string]>(
	"[orbit-secure-store] %s",
	"E_ORBIT_SECURE_STORE_INVALIDATED",
);

/** Anything else the platform reported; never carries the value. */
export const E_ORBIT_SECURE_STORE_FAILED = createError<[string]>(
	"[orbit-secure-store] %s",
	"E_ORBIT_SECURE_STORE_FAILED",
);
