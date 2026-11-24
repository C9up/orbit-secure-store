package com.c9up.orbit.securestore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.UiThreadUtil
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Strings kept encrypted on the phone. Each value is AES-256-GCM ciphertext
 * in a file of the app's no-backup directory — a backup restored elsewhere
 * would carry ciphertext without the key that reads it — under a key that
 * never leaves the Android Keystore. A value set with `requireAuthentication`
 * has a key of its own that only a strong biometric check unlocks, once per
 * use, and that enrolling a new fingerprint invalidates.
 *
 * A value's file is named `<key>.v`: `android.util.AtomicFile` writes beside
 * it `<key>.v.new` (and reads a `<key>.v.bak`), names no key's file can take,
 * so one key never reads, overwrites or deletes another's. The key also goes
 * into the ciphertext as GCM associated data: a value under another name does
 * not decrypt. Values written before (named by the bare key, in the legacy
 * directory) are moved over when they are first read.
 *
 * Nothing here logs a value, a key's material or a ciphertext.
 */
class OrbitSecureStoreModule(context: ReactApplicationContext) : NativeOrbitSecureStoreSpec(context) {
    override fun getName(): String = NAME

    private fun dir(): File = File(reactApplicationContext.noBackupFilesDir, DIR).apply { mkdirs() }

    private fun file(key: String): AtomicFile = AtomicFile(File(dir(), fileName(key)))

    /** Where 0.1.0 kept a value: a file named by the bare key (never written now). */
    private fun legacyFile(key: String): File = File(File(reactApplicationContext.noBackupFilesDir, LEGACY_DIR), key)

    /** Drop a value 0.1.0 kept, and its directory once nothing is left in it. */
    private fun dropLegacy(key: String) {
        val legacy = legacyFile(key)
        if (legacy.isFile) legacy.delete()
        legacy.parentFile?.delete()
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun alias(key: String, auth: Boolean): String = if (auth) "$ALIAS.auth:$key" else ALIAS

    private fun secretKey(alias: String, auth: Boolean): SecretKey {
        val existing = keyStore().getKey(alias, null)
        if (existing is SecretKey) return existing
        val spec =
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .apply {
                    if (auth) {
                        setUserAuthenticationRequired(true)
                        setInvalidatedByBiometricEnrollment(true)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            // Each use, a strong biometric: no time window.
                            setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                        } else {
                            @Suppress("DEPRECATION")
                            setUserAuthenticationValidityDurationSeconds(-1)
                        }
                    }
                }
                .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
            init(spec)
            generateKey()
        }
    }

    private fun validKey(key: String, promise: Promise): Boolean {
        if (KEY_PATTERN.matches(key) && key != "." && key != "..") return true
        promise.reject(INVALID_KEY, "a key is 1 to 128 of A-Z a-z 0-9 . _ -")
        return false
    }

    /** Runs `work` off the UI thread and turns a failure into a named rejection. */
    private fun guarded(promise: Promise, work: () -> Unit) {
        try {
            work()
        } catch (error: KeyPermanentlyInvalidatedException) {
            promise.reject(INVALIDATED, "a new biometric was enrolled: the value it protected is gone", error)
        } catch (error: Exception) {
            // The exception's class only: its message may hold platform detail, never a value.
            promise.reject(FAILED, "the secure store failed (${error.javaClass.simpleName})", error)
        }
    }

    override fun setItem(key: String, value: String, options: ReadableMap, promise: Promise) {
        if (!validKey(key, promise)) return
        val auth = options.hasKey("requireAuthentication") && options.getBoolean("requireAuthentication")
        guarded(promise) {
            val alias = alias(key, auth)
            if (auth) {
                // A new key for a new value: a stale one may have been invalidated.
                keyStore().deleteEntry(alias)
                if (!enrolled(promise)) return@guarded
            }
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey(alias, auth))
            val write = { ready: Cipher ->
                guarded(promise) {
                    ready.updateAAD(associated(key))
                    val sealed = ready.doFinal(value.toByteArray(Charsets.UTF_8))
                    store(key, flags(auth, bound = true), ready.iv, sealed)
                    dropLegacy(key)
                    promise.resolve(null)
                }
            }
            if (auth) authenticate(cipher, options, promise, write) else write(cipher)
        }
    }

    override fun getItem(key: String, options: ReadableMap, promise: Promise) {
        if (!validKey(key, promise)) return
        guarded(promise) {
            val current = file(key).let { if (it.baseFile.exists()) it.readFully() else null }
            // A value 0.1.0 kept: read once from its old file (as a plain file, so
            // nothing beside it is renamed or deleted), then moved over.
            val legacy = legacyFile(key)
            val migrating = current == null && legacy.isFile
            val bytes = current ?: if (migrating) legacy.readBytes() else null
            if (bytes == null || bytes.size < 3) {
                promise.resolve(null)
                return@guarded
            }
            val auth = bytes[0].toInt() and FLAG_AUTH != 0
            val bound = bytes[0].toInt() and FLAG_BOUND != 0
            val ivLength = bytes[1].toInt()
            // Every value this version writes is bound to its key; only a value
            // protected by its own per-key alias may come unbound from 0.1.0.
            if (bytes.size < 2 + ivLength || (!bound && !auth && !migrating)) {
                promise.reject(FAILED, "a stored value is damaged")
                return@guarded
            }
            val iv = bytes.copyOfRange(2, 2 + ivLength)
            val sealed = bytes.copyOfRange(2 + ivLength, bytes.size)
            val alias = alias(key, auth)
            val stored = keyStore().getKey(alias, null)
            if (stored !is SecretKey) {
                // Its key is gone (the app's data restored without its Keystore): unreadable.
                file(key).delete()
                dropLegacy(key)
                promise.reject(INVALIDATED, "the key that protected this value is gone")
                return@guarded
            }
            val cipher = Cipher.getInstance(TRANSFORMATION)
            try {
                cipher.init(Cipher.DECRYPT_MODE, stored, GCMParameterSpec(128, iv))
            } catch (error: KeyPermanentlyInvalidatedException) {
                keyStore().deleteEntry(alias)
                file(key).delete()
                dropLegacy(key)
                throw error
            }
            val read = { ready: Cipher ->
                guarded(promise) {
                    if (bound) ready.updateAAD(associated(key))
                    val plain = ready.doFinal(sealed)
                    if (migrating) migrate(key, auth, bytes, plain)
                    promise.resolve(String(plain, Charsets.UTF_8))
                }
            }
            if (auth) authenticate(cipher, options, promise, read) else read(cipher)
        }
    }

    override fun deleteItem(key: String, promise: Promise) {
        if (!validKey(key, promise)) return
        guarded(promise) {
            file(key).delete()
            dropLegacy(key)
            keyStore().deleteEntry(alias(key, true))
            promise.resolve(null)
        }
    }

    override fun biometricStatus(promise: Promise) {
        val status = BiometricManager.from(reactApplicationContext).canAuthenticate(BIOMETRIC_STRONG)
        promise.resolve(
            Arguments.createMap().apply {
                putBoolean(
                    "hardware",
                    status != BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE &&
                        status != BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE,
                )
                putBoolean("enrolled", status == BiometricManager.BIOMETRIC_SUCCESS)
            },
        )
    }

    private fun enrolled(promise: Promise): Boolean {
        val status = BiometricManager.from(reactApplicationContext).canAuthenticate(BIOMETRIC_STRONG)
        if (status == BiometricManager.BIOMETRIC_SUCCESS) return true
        promise.reject(NO_BIOMETRICS, "this phone has no strong biometric enrolled to protect the value")
        return false
    }

    private fun flags(auth: Boolean, bound: Boolean): Int = (if (auth) FLAG_AUTH else 0) or (if (bound) FLAG_BOUND else 0)

    /** The associated data a value is sealed with: its key, so it opens under no other. */
    private fun associated(key: String): ByteArray = "$ALIAS:$key".toByteArray(Charsets.UTF_8)

    private fun store(key: String, flags: Int, iv: ByteArray, sealed: ByteArray) {
        write(key, byteArrayOf(flags.toByte(), iv.size.toByte()) + iv + sealed)
    }

    private fun write(key: String, bytes: ByteArray) {
        val atomic = file(key)
        val out = atomic.startWrite()
        try {
            out.write(bytes)
            atomic.finishWrite(out)
        } catch (error: Exception) {
            atomic.failWrite(out)
            throw error
        }
    }

    /**
     * Move a value 0.1.0 kept to its new file. One under the shared alias is
     * sealed again, bound to its key; one under its own biometric alias (that
     * alias already names the key, and sealing again would take a second
     * biometric check) keeps its bytes.
     */
    private fun migrate(key: String, auth: Boolean, bytes: ByteArray, plain: ByteArray) {
        if (auth) {
            write(key, bytes)
        } else {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey(ALIAS, false))
            cipher.updateAAD(associated(key))
            store(key, flags(auth = false, bound = true), cipher.iv, cipher.doFinal(plain))
        }
        dropLegacy(key)
    }

    /** Unlock `cipher` with a biometric prompt, then hand it to `use`. */
    private fun authenticate(cipher: Cipher, options: ReadableMap, promise: Promise, use: (Cipher) -> Unit) {
        val activity = reactApplicationContext.currentActivity
        if (activity !is FragmentActivity) {
            promise.reject(FAILED, "no activity on screen to ask for the biometric check")
            return
        }
        val text = { name: String, fallback: String ->
            if (options.hasKey(name) && !options.getString(name).isNullOrEmpty()) options.getString(name) ?: fallback else fallback
        }
        val info =
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(text("promptTitle", "Unlock"))
                .setSubtitle(text("promptSubtitle", ""))
                .setNegativeButtonText(text("promptCancel", "Cancel"))
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .build()
        UiThreadUtil.runOnUiThread {
            val prompt =
                BiometricPrompt(
                    activity,
                    ContextCompat.getMainExecutor(activity),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            val unlocked = result.cryptoObject?.cipher
                            if (unlocked == null) {
                                promise.reject(FAILED, "the biometric check returned no key")
                            } else {
                                use(unlocked)
                            }
                        }

                        override fun onAuthenticationError(code: Int, message: CharSequence) {
                            val cancelled =
                                code == BiometricPrompt.ERROR_USER_CANCELED ||
                                    code == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                                    code == BiometricPrompt.ERROR_CANCELED
                            promise.reject(if (cancelled) CANCELLED else AUTH_FAILED, message.toString())
                        }
                    },
                )
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        }
    }

    companion object {
        const val NAME = "OrbitSecureStore"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "c9up.orbit.secure-store"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val FLAG_AUTH = 1

        /** The value was sealed with its key as associated data. */
        private const val FLAG_BOUND = 2
        private const val DIR = "c9up-secure-store-v2"
        private const val LEGACY_DIR = "c9up-secure-store"

        /**
         * A value's file: the key and `.v`. `AtomicFile` keeps `<name>.new` and
         * `<name>.bak` beside it; those end in `.new` / `.bak`, which no
         * `<key>.v` does, so no key's file is another key's side file.
         */
        fun fileName(key: String): String = "$key.v"
        private val KEY_PATTERN = Regex("^[A-Za-z0-9._-]{1,128}$")
        const val INVALID_KEY = "E_ORBIT_SECURE_STORE_INVALID_KEY"
        const val NO_BIOMETRICS = "E_ORBIT_SECURE_STORE_NO_BIOMETRICS"
        const val CANCELLED = "E_ORBIT_SECURE_STORE_AUTH_CANCELLED"
        const val AUTH_FAILED = "E_ORBIT_SECURE_STORE_AUTH_FAILED"
        const val INVALIDATED = "E_ORBIT_SECURE_STORE_INVALIDATED"
        const val FAILED = "E_ORBIT_SECURE_STORE_FAILED"
    }
}
