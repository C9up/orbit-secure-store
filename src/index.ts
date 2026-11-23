/**
 * `@c9up/orbit-secure-store` — strings kept encrypted on the phone, optionally
 * behind a biometric check:
 *
 *     import { getItem, setItem } from '@c9up/orbit-secure-store'
 *     await setItem('session', token)
 *     await setItem('db-key', key, { requireAuthentication: true })
 *     const token = await getItem('session')     // null when there is none
 *
 * On a phone, React Native's bundler takes index.rn.ts, which calls the app's
 * OrbitSecureStore module (the Android Keystore). The browser and the server
 * have no equivalent — a browser's storage is readable by any script on the
 * page — so here every call rejects with `E_ORBIT_SECURE_STORE_UNAVAILABLE`.
 */
import type { Exception } from "@c9up/flare";
import { E_ORBIT_SECURE_STORE_UNAVAILABLE } from "./errors.js";
import {
	type BiometricStatus,
	checkKey,
	type GetItemOptions,
	type SetItemOptions,
} from "./store.js";

export * as errors from "./errors.js";
export type {
	BiometricStatus,
	GetItemOptions,
	PromptText,
	SetItemOptions,
} from "./store.js";

function unavailable(): Exception {
	return new E_ORBIT_SECURE_STORE_UNAVAILABLE([
		"there is no secure store outside a phone: a browser's storage is readable by every script on the page",
	]);
}

/** Keep `value` under `key`, encrypted. */
export async function setItem(
	key: string,
	_value: string,
	_options: SetItemOptions = {},
): Promise<void> {
	checkKey(key);
	throw unavailable();
}

/** The value under `key`, or `null` when there is none. */
export async function getItem(
	key: string,
	_options: GetItemOptions = {},
): Promise<string | null> {
	checkKey(key);
	throw unavailable();
}

/** Forget the value under `key` (nothing happens when there is none). */
export async function deleteItem(key: string): Promise<void> {
	checkKey(key);
	throw unavailable();
}

/** Whether a strong biometric can protect a value here. */
export async function biometricStatus(): Promise<BiometricStatus> {
	return { hardware: false, enrolled: false };
}
