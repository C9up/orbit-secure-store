import type { TurboModule } from "react-native";
import { TurboModuleRegistry } from "react-native";

/**
 * Strings kept encrypted on the phone (android/…/OrbitSecureStoreModule.kt):
 * AES-256-GCM under a key in the Android Keystore, optionally one that only a
 * biometric check unlocks. Rejections carry an `E_ORBIT_SECURE_STORE_*` code.
 */
export interface Spec extends TurboModule {
	readonly setItem: (
		key: string,
		value: string,
		options: {
			requireAuthentication: boolean;
			promptTitle: string;
			promptSubtitle: string;
			promptCancel: string;
		},
	) => Promise<void>;
	readonly getItem: (
		key: string,
		options: {
			promptTitle: string;
			promptSubtitle: string;
			promptCancel: string;
		},
	) => Promise<string | null>;
	readonly deleteItem: (key: string) => Promise<void>;
	readonly biometricStatus: () => Promise<{
		hardware: boolean;
		enrolled: boolean;
	}>;
}

export default TurboModuleRegistry.getEnforcing<Spec>("OrbitSecureStore");
