/*
 * Copyright 2024 Karma Krafts & associates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.karma.evince.krypton

import io.karma.evince.krypton.annotations.UncheckedKryptonAPI
import io.karma.evince.krypton.internal.openssl.*
import io.karma.evince.krypton.key.Key
import io.karma.evince.krypton.key.KeyType
import io.karma.evince.krypton.utils.ErrorHelper
import io.karma.evince.krypton.utils.checkNotNull
import io.karma.evince.krypton.utils.withFreeWithException
import kotlinx.cinterop.*

/** @suppress **/
actual class Cipher actual constructor(
    algorithm: Algorithm,
    private val key: Key,
    private val parameters: CipherParameters
) : AutoCloseable {
    private val cipher: CPointer<EVP_CIPHER> = getEVPCipher(
        algorithm.toString(),
        requireNotNull(parameters.blockMode ?: algorithm.defaultBlockMode), key.size()
    )
    
    @UncheckedKryptonAPI
    actual constructor(algorithm: String, key: Key, parameters: CipherParameters) :
            this(requireNotNull(Algorithm.firstOrNull(algorithm)), key, parameters)
    
    init {
        algorithm.checkScopeOrError(Algorithm.Scope.CIPHER)
        parameters.validate(algorithm)
        
        if (key.type != KeyType.SYMMETRIC || key.body !is Key.KeyBody.DataKeyBody)
            throw IllegalArgumentException("Invalid type '${key.type}', expected '${KeyType.SYMMETRIC}'")
    }
    
    actual fun process(data: ByteArray, aad: ByteArray?): ByteArray = withFreeWithException {
        val ctx = EVP_CIPHER_CTX_new().checkNotNull().freeAfter(::EVP_CIPHER_CTX_free)
        memScoped {
            // Acquire pointer from key data
            val keyPointer = allocPointerTo<BUF_MEM>()
            if (BIO_ctrl(
                    (key.body as Key.KeyBody.DataKeyBody).data,
                    BIO_C_GET_BUF_MEM_PTR,
                    0,
                    keyPointer.ptr
                ).toLong() != 1L
            )
                throw RuntimeException("Unable to get key memory", ErrorHelper.createOpenSSLException())
            
            // Initialize cipher for encryption or decryption with key, algorithm and optionally IV
            parameters.iv?.pin().apply {
                val keyPtr = keyPointer.pointed.checkNotNull().data.checkNotNull().reinterpret<UByteVar>()
                when (parameters.mode) {
                    Mode.ENCRYPT -> {
                        if (EVP_EncryptInit(ctx, cipher, keyPtr, this?.addressOf(0)?.reinterpret()) != 1) {
                            throw RuntimeException(
                                "Unable to init encryption cipher",
                                ErrorHelper.createOpenSSLException()
                            )
                        }
                    }
                    
                    Mode.DECRYPT -> {
                        if (EVP_DecryptInit(ctx, cipher, keyPtr, this?.addressOf(0)?.reinterpret()) != 1) {
                            throw RuntimeException(
                                "Unable to init decryption cipher",
                                ErrorHelper.createOpenSSLException()
                            )
                        }
                    }
                }
            }?.unpin()
            
            val blockSize = EVP_CIPHER_CTX_get_block_size(ctx)
            val encryptedSize = alloc<Int>(0)
            val paddingSize = alloc<Int>(0)
            ByteArray(data.size + blockSize).also {
                it.usePinned { output ->
                    when (parameters.mode) {
                        Mode.ENCRYPT -> {
                            data.usePinned { input ->
                                if (EVP_EncryptUpdate(
                                        ctx,
                                        output.addressOf(0).reinterpret(),
                                        encryptedSize.ptr,
                                        input.addressOf(0).reinterpret(),
                                        data.size
                                    ) != 1
                                ) {
                                    throw RuntimeException(
                                        "Unable to encrypt data",
                                        ErrorHelper.createOpenSSLException()
                                    )
                                }
                            }
                            
                            if (EVP_EncryptFinal(
                                    ctx,
                                    output.addressOf(encryptedSize.value).reinterpret(),
                                    paddingSize.ptr
                                ) != 1
                            ) {
                                throw RuntimeException(
                                    "Unable to finalize encryption",
                                    ErrorHelper.createOpenSSLException()
                                )
                            }
                        }
                        
                        Mode.DECRYPT -> {
                            data.usePinned { input ->
                                if (EVP_DecryptUpdate(
                                        ctx,
                                        output.addressOf(0).reinterpret(),
                                        encryptedSize.ptr,
                                        input.addressOf(0).reinterpret(),
                                        data.size
                                    ) != 1
                                ) {
                                    throw RuntimeException(
                                        "Unable to decrypt data",
                                        ErrorHelper.createOpenSSLException()
                                    )
                                }
                            }
                            
                            if (EVP_DecryptFinal(
                                    ctx,
                                    output.addressOf(encryptedSize.value).reinterpret(),
                                    paddingSize.ptr
                                ) != 1
                            ) {
                                throw RuntimeException(
                                    "Unable to finalize decryption",
                                    ErrorHelper.createOpenSSLException()
                                )
                            }
                        }
                    }
                }
            }.copyOf(encryptedSize.value + paddingSize.value)
        }
    }
    
    actual override fun close() {
        EVP_CIPHER_free(cipher)
    }
    
    actual enum class Mode {
        ENCRYPT, DECRYPT
    }
}

private fun getEVPCipher(algorithm: String, blockMode: BlockMode, bits: Int): CPointer<EVP_CIPHER> =
    requireNotNull(
        when (algorithm) {
            "AES" -> when (blockMode) {
                BlockMode.ECB -> when (bits) {
                    128 -> EVP_aes_128_ecb()
                    192 -> EVP_aes_192_ecb()
                    256 -> EVP_aes_256_ecb()
                    else -> throw IllegalArgumentException("No AES-$bits-EBC available")
                }
                
                BlockMode.CBC -> when (bits) {
                    128 -> EVP_aes_128_cbc()
                    192 -> EVP_aes_192_cbc()
                    256 -> EVP_aes_256_cbc()
                    else -> throw IllegalArgumentException("No AES-$bits-CBC available")
                }
                
                BlockMode.CFB -> when (bits) {
                    128 -> EVP_aes_128_cfb128()
                    else -> throw IllegalArgumentException("No AES-$bits-CFB available")
                }
                
                BlockMode.OFB -> when (bits) {
                    128 -> EVP_aes_128_ofb()
                    192 -> EVP_aes_192_ofb()
                    256 -> EVP_aes_256_ofb()
                    else -> throw IllegalArgumentException("No AES-$bits-OFB available")
                }
                
                BlockMode.OCB -> when (bits) {
                    128 -> EVP_aes_128_ocb()
                    192 -> EVP_aes_192_ocb()
                    256 -> EVP_aes_256_ocb()
                    else -> throw IllegalArgumentException("No AES-$bits-OCB available")
                }
                
                BlockMode.CTR -> when (bits) {
                    128 -> EVP_aes_128_ctr()
                    192 -> EVP_aes_192_ctr()
                    256 -> EVP_aes_256_ctr()
                    else -> throw IllegalArgumentException("No AES-$bits-CTR available")
                }
                
                BlockMode.GCM -> when (bits) {
                    128 -> EVP_aes_128_gcm()
                    192 -> EVP_aes_192_gcm()
                    256 -> EVP_aes_256_gcm()
                    else -> throw IllegalArgumentException("No AES-$bits-GCM available")
                }
            }
            
            else -> throw IllegalArgumentException("Unsupported algorithm '$algorithm'")
        }
    )