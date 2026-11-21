/**
 * orbit-secure-store's errors: a stable `code` (`E_ORBIT_SECURE_STORE_<REASON>`)
 * for a caller to branch on. A cancelled biometric check is not a failed one.
 */
export type OrbitSecureStoreErrorCode =
	/** No secure store here: the browser, the server, an app built without the module. */
	| "E_ORBIT_SECURE_STORE_UNAVAILABLE"
	/** A key that is not 1 to 128 of `A-Z a-z 0-9 . _ -`. */
	| "E_ORBIT_SECURE_STORE_INVALID_KEY"
	/** `requireAuthentication` on a phone with no strong biometric enrolled. */
	| "E_ORBIT_SECURE_STORE_NO_BIOMETRICS"
	/** The user dismissed the biometric prompt. */
	| "E_ORBIT_SECURE_STORE_AUTH_CANCELLED"
	/** The biometric check failed for good (too many attempts, a lockout, a hardware error). */
	| "E_ORBIT_SECURE_STORE_AUTH_FAILED"
	/** The key behind the value is gone (a new biometric enrolled, the app's data restored): the value with it. */
	| "E_ORBIT_SECURE_STORE_INVALIDATED"
	/** Anything else the platform reported; never carries the value. */
	| "E_ORBIT_SECURE_STORE_FAILED";

const CODES: ReadonlySet<string> = new Set<OrbitSecureStoreErrorCode>([
	"E_ORBIT_SECURE_STORE_UNAVAILABLE",
	"E_ORBIT_SECURE_STORE_INVALID_KEY",
	"E_ORBIT_SECURE_STORE_NO_BIOMETRICS",
	"E_ORBIT_SECURE_STORE_AUTH_CANCELLED",
	"E_ORBIT_SECURE_STORE_AUTH_FAILED",
	"E_ORBIT_SECURE_STORE_INVALIDATED",
	"E_ORBIT_SECURE_STORE_FAILED",
]);

export function isOrbitSecureStoreErrorCode(
	value: unknown,
): value is OrbitSecureStoreErrorCode {
	return typeof value === "string" && CODES.has(value);
}

export class OrbitSecureStoreError extends Error {
	readonly code: OrbitSecureStoreErrorCode;

	constructor(
		code: OrbitSecureStoreErrorCode,
		message: string,
		options?: ErrorOptions,
	) {
		super(message, options);
		this.name = "OrbitSecureStoreError";
		this.code = code;
	}
}

/** What setItem takes beyond the key and the value. */
export interface SetItemOptions {
	/** Readable only after a strong biometric check, each time. */
	requireAuthentication?: boolean;
	/** The biometric prompt's words, when one is shown. */
	prompt?: PromptText;
}

/** What getItem takes beyond the key. */
export interface GetItemOptions {
	/** The biometric prompt's words, when the value requires one. */
	prompt?: PromptText;
}

export interface PromptText {
	title?: string;
	subtitle?: string;
	/** The button that dismisses it. */
	cancel?: string;
}

export interface BiometricStatus {
	/** The phone has a strong biometric sensor it can use. */
	hardware: boolean;
	/** One is enrolled: `requireAuthentication` will work. */
	enrolled: boolean;
}

const KEY = /^[A-Za-z0-9._-]{1,128}$/;

/** A key as the store accepts it, refused before anything crosses. */
export function checkKey(key: string): void {
	if (!KEY.test(key) || key === "." || key === "..") {
		throw new OrbitSecureStoreError(
			"E_ORBIT_SECURE_STORE_INVALID_KEY",
			"[orbit-secure-store] a key is 1 to 128 of A-Z a-z 0-9 . _ -",
		);
	}
}
