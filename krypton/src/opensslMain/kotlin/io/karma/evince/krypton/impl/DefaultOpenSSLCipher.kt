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

package io.karma.evince.krypton.impl

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.Cipher
import io.karma.evince.krypton.DefaultAlgorithm
import io.karma.evince.krypton.InitializationException
import io.karma.evince.krypton.OpenSSLException
import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.internal.openssl.*
import io.karma.evince.krypton.openssl.asymmetricCipher
import io.karma.evince.krypton.openssl.symmetricCipher
import io.karma.evince.krypton.parameters.CipherParameters

class DefaultOpenSSLCipher(private val parameters: CipherParameters) : Cipher {
    private val algorithm: Algorithm = parameters.key.algorithm
    private val closure: (CipherParameters, ByteArray, ByteArray?) -> ByteArray = INTERNAL_FACTORIES[algorithm.literal]
        ?: throw InitializationException("Algorithm '${algorithm.literal}' is not supported")

    override suspend fun run(input: ByteArray, aad: ByteArray?): ByteArray = closure(parameters, input, aad)

    companion object {
        /** @suppress **/
        @InternalKryptonAPI
        private val INTERNAL_FACTORIES: MutableMap<String, (CipherParameters, ByteArray, ByteArray?) -> ByteArray> =
            mutableMapOf()


        init {
            registerCipherClosure(DefaultAlgorithm.RSA, asymmetricCipher { context, parameters ->
                when (val padding = requireNotNull((parameters.padding ?: DefaultAlgorithm.RSA.defaultBlockMode))) {
                    Algorithm.Padding.NONE, Algorithm.Padding.PKCS1 -> {
                        if (EVP_PKEY_CTX_set_rsa_padding(
                                ctx = context,
                                pad_mode = if (padding == Algorithm.Padding.NONE) RSA_NO_PADDING else RSA_PKCS1_PADDING
                            ) != 1
                        ) {
                            throw InitializationException("Unable to set padding", OpenSSLException.create())
                        }
                    }

                    Algorithm.Padding.OAEP_SHA256, Algorithm.Padding.OAEP_SHA1 -> {
                        if (EVP_PKEY_CTX_set_rsa_oaep_md(
                                ctx = context,
                                md = if (padding == Algorithm.Padding.OAEP_SHA1) EVP_sha1() else EVP_sha256()
                            ) != 1
                        ) {
                            throw InitializationException("Unable to set OAEP digest", OpenSSLException.create())
                        }
                    }

                    else -> throw RuntimeException("Padding '$padding' not supported for RSA")
                }
            })
            registerCipherClosure(DefaultAlgorithm.AES, symmetricCipher(true) { key, parameters ->
                when (requireNotNull(parameters.blockMode ?: DefaultAlgorithm.AES.defaultBlockMode)) {
                    Algorithm.BlockMode.ECB -> when (key.size()) {
                        128 -> EVP_aes_128_ecb()
                        192 -> EVP_aes_192_ecb()
                        256 -> EVP_aes_256_ecb()
                        else -> throw IllegalArgumentException("No AES-${key.size()}-EBC available")
                    }

                    Algorithm.BlockMode.CBC -> when (key.size()) {
                        128 -> EVP_aes_128_cbc()
                        192 -> EVP_aes_192_cbc()
                        256 -> EVP_aes_256_cbc()
                        else -> throw IllegalArgumentException("No AES-${key.size()}-CBC available")
                    }

                    Algorithm.BlockMode.OFB -> when (key.size()) {
                        128 -> EVP_aes_128_ofb()
                        192 -> EVP_aes_192_ofb()
                        256 -> EVP_aes_256_ofb()
                        else -> throw IllegalArgumentException("No AES-${key.size()}-OFB available")
                    }

                    Algorithm.BlockMode.CTR -> when (key.size()) {
                        128 -> EVP_aes_128_ctr()
                        192 -> EVP_aes_192_ctr()
                        256 -> EVP_aes_256_ctr()
                        else -> throw IllegalArgumentException("No AES-${key.size()}-CTR available")
                    }

                    Algorithm.BlockMode.GCM -> when (key.size()) {
                        128 -> EVP_aes_128_gcm()
                        192 -> EVP_aes_192_gcm()
                        256 -> EVP_aes_256_gcm()
                        else -> throw IllegalArgumentException("No AES-${key.size()}-GCM available")
                    }
                }
            })
        }

        /** @suppress **/
        @InternalKryptonAPI
        fun registerCipherClosure(algorithm: Algorithm, cipher: (CipherParameters, ByteArray, ByteArray?) -> ByteArray) {
            INTERNAL_FACTORIES[algorithm.literal] = cipher
        }

    }
}