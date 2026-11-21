package com.c9up.orbit.securestore

import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfo
import com.facebook.react.module.model.ReactModuleInfoProvider

/** What React Native's autolinking registers: the OrbitSecureStore TurboModule. */
class OrbitSecureStorePackage : BaseReactPackage() {
    override fun getModule(name: String, reactContext: ReactApplicationContext): NativeModule? =
        if (name == OrbitSecureStoreModule.NAME) OrbitSecureStoreModule(reactContext) else null

    override fun getReactModuleInfoProvider(): ReactModuleInfoProvider =
        ReactModuleInfoProvider {
            mapOf(
                OrbitSecureStoreModule.NAME to
                    ReactModuleInfo(
                        OrbitSecureStoreModule.NAME,
                        OrbitSecureStoreModule.NAME,
                        false, // canOverrideExistingModule
                        false, // needsEagerInit
                        false, // isCxxModule
                        true, // isTurboModule
                    ),
            )
        }
}
