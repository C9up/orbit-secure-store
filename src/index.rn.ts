/**
 * `@c9up/orbit-secure-store` on a phone: the app's OrbitSecureStore TurboModule
 * (android/…/OrbitSecureStoreModule.kt), which React Native's autolinking adds
 * to an app built by `ream android:*`. React Native's bundler takes this file
 * in place of index.ts; it exports what index.ts exports.
 */
import {
	type BiometricStatus,
	checkKey,
	type GetItemOptions,
	isOrbitSecureStoreErrorCode,
	OrbitSecureStoreError,
	type PromptText,
	type SetItemOptions,
} from "./errors.js";

export {
	type BiometricStatus,
	type GetItemOptions,
	OrbitSecureStoreError,
	type OrbitSecureStoreErrorCode,
	type PromptText,
	type SetItemOptions,
} from "./errors.js";

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
		throw new OrbitSecureStoreError(
			"E_ORBIT_SECURE_STORE_UNAVAILABLE",
			"[orbit-secure-store] the OrbitSecureStore module is not in the app: build it with `ream android:*`, whose autolinking adds it",
		);
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
function failure(error: unknown): OrbitSecureStoreError {
	const code: unknown =
		typeof error === "object" && error !== null
			? Reflect.get(error, "code")
			: undefined;
	return new OrbitSecureStoreError(
		isOrbitSecureStoreErrorCode(code) ? code : "E_ORBIT_SECURE_STORE_FAILED",
		`[orbit-secure-store] ${error instanceof Error ? error.message : String(error)}`,
		{ cause: error },
	);
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
