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

package io.karma.evince.krypton.internal.cipher

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.BlockMode
import io.karma.evince.krypton.Cipher
import io.karma.evince.krypton.CipherParameters
import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.internal.openssl.*
import io.karma.evince.krypton.key.Key
import io.karma.evince.krypton.utils.ErrorHelper
import io.karma.evince.krypton.utils.checkNotNull
import io.karma.evince.krypton.utils.withFreeWithException
import kotlinx.cinterop.*

/** @suppress **/
@InternalKryptonAPI
open class OpenSSLSymmetricCipher<P : CipherParameters>(
    private val cipher: CPointer<EVP_CIPHER>,
    private val algorithm: Algorithm,
    private val parameters: P,
    key: Key
) : InternalCipher {
    private val keyData = (key.body as Key.KeyBody.DataKeyBody).data
    
    override fun process(data: ByteArray, aad: ByteArray?): ByteArray = withFreeWithException {
        val context = EVP_CIPHER_CTX_new().checkNotNull().freeAfter(::EVP_CIPHER_CTX_free)
        memScoped {
            val keyPointer = allocPointerTo<BUF_MEM>()
            if (BIO_ctrl(keyData, BIO_C_GET_BUF_MEM_PTR, 0, keyPointer.ptr).toLong() != 1L)
                throw RuntimeException("Unable to get key memory", ErrorHelper.createOpenSSLException())
            
            // Initialize encryption/decryption context for operation
            val keyPtr = keyPointer.pointed.checkNotNull().data.checkNotNull().reinterpret<UByteVar>()
            if (parameters.iv != null) {
                parameters.iv.usePinned {
                    initContext(context, keyPtr, it.addressOf(0).reinterpret())
                }
            } else {
                initContext(context, keyPtr, null)
            }
            
            val offset = if (algorithm.blockCipher) EVP_CIPHER_CTX_get_block_size(context) else 0
            val updateOutputSize = alloc<Int>(0)
            val finalizeOutputSize = alloc<Int>(0)
            ByteArray(data.size + offset).also {
                // Update cipher with new input data
                it.usePinned { output ->
                    data.usePinned { input ->
                        when (parameters.mode) {
                            Cipher.Mode.ENCRYPT -> {
                                // Update encryption cipher
                                if (EVP_EncryptUpdate(
                                        ctx = context,
                                        out = output.addressOf(0).reinterpret(),
                                        outl = updateOutputSize.ptr,
                                        `in` = input.addressOf(0).reinterpret(),
                                        inl = data.size
                                    ) != 1
                                ) {
                                    throw RuntimeException(
                                        "Unable to update cipher for encryption",
                                        ErrorHelper.createOpenSSLException()
                                    )
                                }
                                
                                // Finalize encryption
                                if (EVP_EncryptFinal(
                                        ctx = context,
                                        out = output.addressOf(updateOutputSize.value).reinterpret(),
                                        outl = finalizeOutputSize.ptr
                                    ) != 1
                                ) {
                                    throw RuntimeException(
                                        "Unable to finalize encryption",
                                        ErrorHelper.createOpenSSLException()
                                    )
                                }
                            }
                            
                            Cipher.Mode.DECRYPT -> {
                                // Update decryption cipher
                                if (EVP_DecryptUpdate(
                                        ctx = context,
                                        out = output.addressOf(0).reinterpret(),
                                        outl = updateOutputSize.ptr,
                                        `in` = input.addressOf(0).reinterpret(),
                                        inl = data.size
                                    ) != 1
                                ) {
                                    throw RuntimeException(
                                        "Unable to update cipher for decryption",
                                        ErrorHelper.createOpenSSLException()
                                    )
                                }
                                
                                // Finalize decryption
                                if (EVP_DecryptFinal(
                                        ctx = context,
                                        outm = output.addressOf(updateOutputSize.value).reinterpret(),
                                        outl = finalizeOutputSize.ptr
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
                }
            }.copyOf(updateOutputSize.value + finalizeOutputSize.value)
        }
    }
    
    private fun initContext(context: CPointer<EVP_CIPHER_CTX>, keyPtr: CPointer<UByteVar>, iv: CPointer<UByteVar>?) {
        when (parameters.mode) {
            Cipher.Mode.ENCRYPT -> {
                if (EVP_EncryptInit(context, cipher, keyPtr, iv) != 1)
                    throw RuntimeException("Unable to initialize encryption", ErrorHelper.createOpenSSLException())
            }
            
            Cipher.Mode.DECRYPT -> {
                if (EVP_DecryptInit(context, cipher, keyPtr, iv) != 1)
                    throw RuntimeException("Unable to initialize decryption", ErrorHelper.createOpenSSLException())
            }
        }
    }
    
    override fun close() {
        EVP_CIPHER_free(cipher)
    }
}

/** @suppress **/
@InternalKryptonAPI
internal class AESCipher(key: Key, parameters: CipherParameters) : OpenSSLSymmetricCipher<CipherParameters>(
    cipher = when (requireNotNull(parameters.blockMode ?: Algorithm.AES.defaultBlockMode)) {
        BlockMode.ECB -> when (key.size()) {
            128 -> EVP_aes_128_ecb()
            192 -> EVP_aes_192_ecb()
            256 -> EVP_aes_256_ecb()
            else -> throw IllegalArgumentException("No AES-${key.size()}-EBC available")
        }
        
        BlockMode.CBC -> when (key.size()) {
            128 -> EVP_aes_128_cbc()
            192 -> EVP_aes_192_cbc()
            256 -> EVP_aes_256_cbc()
            else -> throw IllegalArgumentException("No AES-${key.size()}-CBC available")
        }
        
        BlockMode.CFB -> when (key.size()) {
            128 -> EVP_aes_128_cfb128()
            else -> throw IllegalArgumentException("No AES-${key.size()}-CFB available")
        }
        
        BlockMode.OFB -> when (key.size()) {
            128 -> EVP_aes_128_ofb()
            192 -> EVP_aes_192_ofb()
            256 -> EVP_aes_256_ofb()
            else -> throw IllegalArgumentException("No AES-${key.size()}-OFB available")
        }
        
        BlockMode.OCB -> when (key.size()) {
            128 -> EVP_aes_128_ocb()
            192 -> EVP_aes_192_ocb()
            256 -> EVP_aes_256_ocb()
            else -> throw IllegalArgumentException("No AES-${key.size()}-OCB available")
        }
        
        BlockMode.CTR -> when (key.size()) {
            128 -> EVP_aes_128_ctr()
            192 -> EVP_aes_192_ctr()
            256 -> EVP_aes_256_ctr()
            else -> throw IllegalArgumentException("No AES-${key.size()}-CTR available")
        }
        
        BlockMode.GCM -> when (key.size()) {
            128 -> EVP_aes_128_gcm()
            192 -> EVP_aes_192_gcm()
            256 -> EVP_aes_256_gcm()
            else -> throw IllegalArgumentException("No AES-${key.size()}-GCM available")
        }
    }.checkNotNull(),
    algorithm = Algorithm.AES,
    parameters = parameters,
    key = key
)
