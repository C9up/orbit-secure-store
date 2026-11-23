/**
 * `@c9up/orbit-secure-store` on a phone: the app's OrbitSecureStore TurboModule
 * (android/…/OrbitSecureStoreModule.kt), which React Native's autolinking adds
 * to an app built by `ream android:*`. React Native's bundler takes this file
 * in place of index.ts; it exports what index.ts exports.
 */
import type { ErrorClass, Exception } from "@c9up/flare";
import * as errors from "./errors.js";
import {
	type BiometricStatus,
	checkKey,
	type GetItemOptions,
	type PromptText,
	type SetItemOptions,
} from "./store.js";

export * as errors from "./errors.js";
export type {
	BiometricStatus,
	GetItemOptions,
	PromptText,
	SetItemOptions,
} from "./store.js";

/** The codes the native module rejects with, each to its error. */
const NATIVE_CODES: ReadonlyMap<string, ErrorClass<[string]>> = new Map([
	["E_ORBIT_SECURE_STORE_UNAVAILABLE", errors.E_ORBIT_SECURE_STORE_UNAVAILABLE],
	["E_ORBIT_SECURE_STORE_INVALID_KEY", errors.E_ORBIT_SECURE_STORE_INVALID_KEY],
	[
		"E_ORBIT_SECURE_STORE_NO_BIOMETRICS",
		errors.E_ORBIT_SECURE_STORE_NO_BIOMETRICS,
	],
	[
		"E_ORBIT_SECURE_STORE_AUTH_CANCELLED",
		errors.E_ORBIT_SECURE_STORE_AUTH_CANCELLED,
	],
	["E_ORBIT_SECURE_STORE_AUTH_FAILED", errors.E_ORBIT_SECURE_STORE_AUTH_FAILED],
	["E_ORBIT_SECURE_STORE_INVALIDATED", errors.E_ORBIT_SECURE_STORE_INVALIDATED],
	["E_ORBIT_SECURE_STORE_FAILED", errors.E_ORBIT_SECURE_STORE_FAILED],
]);

interface NativePrompt {
	promptTitle: string;
	promptSubtitle: string;
	promptCancel: string;
}

interface NativeSecureStore {
	setItem(
		key: string,
		value: string,
		options: NativePrompt & { requireAuthentication: boolean },
	): Promise<void>;
	getItem(key: string, options: NativePrompt): Promise<string | null>;
	deleteItem(key: string): Promise<void>;
	biometricStatus(): Promise<BiometricStatus>;
}

function isNativeSecureStore(value: unknown): value is NativeSecureStore {
	return (
		typeof value === "object" &&
		value !== null &&
		["setItem", "getItem", "deleteItem", "biometricStatus"].every(
			(name) => typeof Reflect.get(value, name) === "function",
		)
	);
}

/**
 * OrbitSecureStore, as TurboModuleRegistry finds a module: the TurboModule
 * proxy, then `nativeModuleProxy` — the only one a bridgeless app installs.
 */
function lookup(): NativeSecureStore | undefined {
	const proxy: unknown = Reflect.get(globalThis, "__turboModuleProxy");
	if (typeof proxy === "function") {
		const module: unknown = Reflect.apply(proxy, undefined, [
			"OrbitSecureStore",
		]);
		if (isNativeSecureStore(module)) return module;
	}
	const modules: unknown = Reflect.get(globalThis, "nativeModuleProxy");
	if (typeof modules === "object" && modules !== null) {
		const module: unknown = Reflect.get(modules, "OrbitSecureStore");
		if (isNativeSecureStore(module)) return module;
	}
	return undefined;
}

let cached: NativeSecureStore | undefined;

function native(): NativeSecureStore {
	cached ??= lookup();
	if (cached === undefined) {
		throw new errors.E_ORBIT_SECURE_STORE_UNAVAILABLE([
			"the OrbitSecureStore module is not in the app: build it with `ream android:*`, whose autolinking adds it",
		]);
	}
	return cached;
}

function prompt(text: PromptText = {}): NativePrompt {
	return {
		promptTitle: text.title ?? "",
		promptSubtitle: text.subtitle ?? "",
		promptCancel: text.cancel ?? "",
	};
}

/** The module's rejection, under its own code (never the value). */
function failure(error: unknown): Exception {
	const code: unknown =
		typeof error === "object" && error !== null
			? Reflect.get(error, "code")
			: undefined;
	const Failure =
		(typeof code === "string" ? NATIVE_CODES.get(code) : undefined) ??
		errors.E_ORBIT_SECURE_STORE_FAILED;
	return new Failure([error instanceof Error ? error.message : String(error)], {
		cause: error,
	});
}

async function call<T>(run: () => Promise<T>): Promise<T> {
	try {
		return await run();
	} catch (error) {
		throw failure(error);
	}
}

/** Keep `value` under `key`, encrypted; with `requireAuthentication`, behind a biometric check. */
export async function setItem(
	key: string,
	value: string,
	options: SetItemOptions = {},
): Promise<void> {
	checkKey(key);
	const store = native();
	await call(() =>
		store.setItem(key, value, {
			requireAuthentication: options.requireAuthentication === true,
			...prompt(options.prompt),
		}),
	);
}

/** The value under `key`, or `null` when there is none. */
export async function getItem(
	key: string,
	options: GetItemOptions = {},
): Promise<string | null> {
	checkKey(key);
	const store = native();
	return call(() => store.getItem(key, prompt(options.prompt)));
}

/** Forget the value under `key` (nothing happens when there is none). */
export async function deleteItem(key: string): Promise<void> {
	checkKey(key);
	const store = native();
	await call(() => store.deleteItem(key));
}

/** Whether a strong biometric can protect a value on this phone. */
export async function biometricStatus(): Promise<BiometricStatus> {
	const store = native();
	return call(() => store.biometricStatus());
}
