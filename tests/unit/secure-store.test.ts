/**
 * The phone's secure store through the app's module (a fake here, holding
 * values as the Keystore-backed module would), and the browser's refusal.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
	Reflect.deleteProperty(globalThis, "__turboModuleProxy");
	Reflect.deleteProperty(globalThis, "nativeModuleProxy");
	vi.resetModules();
});

interface Call {
	method: string;
	args: unknown[];
}

/** The module: values in a map; a protected read rejects as the prompt answers. */
function fakeModule(answer?: string) {
	const values = new Map<string, { value: string; auth: boolean }>();
	const calls: Call[] = [];
	const reject = (code: string) =>
		Promise.reject(Object.assign(new Error("biometric"), { code }));
	return {
		calls,
		module: {
			setItem: async (
				key: string,
				value: string,
				options: { requireAuthentication: boolean },
			) => {
				calls.push({ method: "setItem", args: [key, "[value]", options] });
				values.set(key, { value, auth: options.requireAuthentication });
			},
			getItem: async (key: string, options: object) => {
				calls.push({ method: "getItem", args: [key, options] });
				const entry = values.get(key);
				if (entry === undefined) return null;
				if (entry.auth && answer !== undefined) return reject(answer);
				return entry.value;
			},
			deleteItem: async (key: string) => {
				values.delete(key);
			},
			biometricStatus: async () => ({ hardware: true, enrolled: true }),
		},
	};
}

describe("on a phone", () => {
	it("exports what the browser entry exports", async () => {
		const web = await import("../../src/index.js");
		const rn = await import("../../src/index.rn.js");
		expect(Object.keys(rn).sort()).toEqual(Object.keys(web).sort());
	});

	it("keeps, reads and forgets a value through the app's module", async () => {
		const fake = fakeModule();
		Reflect.set(globalThis, "nativeModuleProxy", {
			OrbitSecureStore: fake.module,
		});
		const store = await import("../../src/index.rn.js");
		expect(await store.getItem("session")).toBeNull();
		await store.setItem("session", "jwt.abc");
		expect(await store.getItem("session")).toBe("jwt.abc");
		await store.deleteItem("session");
		expect(await store.getItem("session")).toBeNull();
		expect(await store.biometricStatus()).toEqual({
			hardware: true,
			enrolled: true,
		});
		// The prompt's words go to the module, empty when not given.
		await store.setItem("db-key", "k", {
			requireAuthentication: true,
			prompt: { title: "Unlock Tessel" },
		});
		expect(fake.calls.at(-1)?.args[2]).toEqual({
			requireAuthentication: true,
			promptTitle: "Unlock Tessel",
			promptSubtitle: "",
			promptCancel: "",
		});
	});

	it("tells a cancelled biometric check from a failed one, and never a code it does not know", async () => {
		for (const [answer, code] of [
			[
				"E_ORBIT_SECURE_STORE_AUTH_CANCELLED",
				"E_ORBIT_SECURE_STORE_AUTH_CANCELLED",
			],
			["E_ORBIT_SECURE_STORE_AUTH_FAILED", "E_ORBIT_SECURE_STORE_AUTH_FAILED"],
			["E_SOMETHING_ELSE", "E_ORBIT_SECURE_STORE_FAILED"],
		] as const) {
			vi.resetModules();
			const fake = fakeModule(answer);
			Reflect.set(globalThis, "nativeModuleProxy", {
				OrbitSecureStore: fake.module,
			});
			const store = await import("../../src/index.rn.js");
			await store.setItem("db-key", "secret", { requireAuthentication: true });
			const error = await store.getItem("db-key").catch((e: unknown) => e);
			expect(error).toMatchObject({ code });
			expect(error).toBeInstanceOf(store.errors[code]);
		}
	});

	it("refuses a key that is not a plain name before anything crosses, and an app without the module", async () => {
		const fake = fakeModule();
		Reflect.set(globalThis, "nativeModuleProxy", {
			OrbitSecureStore: fake.module,
		});
		const store = await import("../../src/index.rn.js");
		for (const key of ["", "../x", "a/b", ".", "x".repeat(129)]) {
			await expect(store.setItem(key, "v")).rejects.toMatchObject({
				code: "E_ORBIT_SECURE_STORE_INVALID_KEY",
			});
		}
		expect(fake.calls).toEqual([]);
		vi.resetModules();
		Reflect.set(globalThis, "nativeModuleProxy", {});
		const bare = await import("../../src/index.rn.js");
		await expect(bare.getItem("session")).rejects.toMatchObject({
			code: "E_ORBIT_SECURE_STORE_UNAVAILABLE",
		});
	});
});

describe("in the browser and on the server", () => {
	it("has no secure store: every call rejects with a named error", async () => {
		const store = await import("../../src/index.js");
		await expect(store.setItem("session", "v")).rejects.toMatchObject({
			code: "E_ORBIT_SECURE_STORE_UNAVAILABLE",
		});
		await expect(store.getItem("session")).rejects.toMatchObject({
			code: "E_ORBIT_SECURE_STORE_UNAVAILABLE",
		});
		await expect(store.deleteItem("session")).rejects.toMatchObject({
			code: "E_ORBIT_SECURE_STORE_UNAVAILABLE",
		});
		expect(await store.biometricStatus()).toEqual({
			hardware: false,
			enrolled: false,
		});
	});
});
