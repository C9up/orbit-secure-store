/**
 * What both entries share: the options a call takes, and the key check that
 * runs before anything crosses to the platform.
 */
import { E_ORBIT_SECURE_STORE_INVALID_KEY } from "./errors.js";

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
		throw new E_ORBIT_SECURE_STORE_INVALID_KEY([
			"a key is 1 to 128 of A-Z a-z 0-9 . _ -",
		]);
	}
}
