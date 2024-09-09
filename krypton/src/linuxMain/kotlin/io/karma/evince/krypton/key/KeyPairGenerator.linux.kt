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

package io.karma.evince.krypton.key

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.utils.ErrorHelper
import libssl.*

actual class KeyPairGenerator actual constructor(
    algorithm: Algorithm,
    parameter: KeyPairGeneratorParameter
) : AutoCloseable {
    private val keyPairGeneratorImpl: KeyPairGeneratorImpl = when (algorithm) {
        Algorithm.RSA -> RSAKeyPairGeneratorImpl(parameter)
        else -> throw IllegalArgumentException("Algorithm '$algorithm' is not supported")
    }

    actual constructor(
        algorithm: String,
        parameter: KeyPairGeneratorParameter
    ) : this(
        Algorithm.fromLiteral(algorithm, true) ?: throw IllegalArgumentException(
            "The algorithm '$algorithm' is not available, the following are officially supported by Krypton: ${
                Algorithm.entries.filter { it.asymmetric }.joinToString(", ")
            }"
        ), parameter
    )

    actual fun generate(): KeyPair = this.keyPairGeneratorImpl.generate()
    actual override fun close() {
        this.keyPairGeneratorImpl.close()
    }

    interface KeyPairGeneratorImpl {
        fun generate(): KeyPair
        fun close()
    }

    internal class RSAKeyPairGeneratorImpl(private val parameter: KeyPairGeneratorParameter) : KeyPairGeneratorImpl {
        private var bne = BN_new()

        init {
            if (BN_set_word(bne, RSA_F4.toULong()) != 1) {
                BN_free(bne)
                bne = null
                throw RuntimeException(
                    "Initialization of RSA key generator failed",
                    ErrorHelper.createOpenSSLException()
                )
            }
        }

        override fun generate(): KeyPair {
            val rsa = requireNotNull(RSA_new())
            if (RSA_generate_key_ex(rsa, parameter.size, bne, null) != 1) {
                RSA_free(rsa)
                throw RuntimeException("Unable to generate RSA keys", ErrorHelper.createOpenSSLException())
            }

            val privateKey = requireNotNull(EVP_PKEY_new())
            if (EVP_PKEY_set1_RSA(privateKey, rsa) != 1) {
                EVP_PKEY_free(privateKey)
                RSA_free(rsa)
                throw RuntimeException(
                    "Unable to acquire private key from generate keypair",
                    ErrorHelper.createOpenSSLException()
                )
            }

            val publicKey = requireNotNull(EVP_PKEY_new())
            val publicKeyRSA = RSAPublicKey_dup(rsa)
            if (EVP_PKEY_set1_RSA(publicKey, publicKeyRSA) != 1) {
                EVP_PKEY_free(privateKey)
                EVP_PKEY_free(publicKey)
                RSA_free(publicKeyRSA)
                RSA_free(rsa)
                throw RuntimeException(
                    "Unable to acquire public key from generate keypair",
                    ErrorHelper.createOpenSSLException()
                )
            }

            RSA_free(publicKeyRSA)
            RSA_free(rsa)
            return KeyPair(Key(KeyType.PUBLIC, "RSA", publicKey), Key(KeyType.PRIVATE, "RSA", privateKey))
        }

        override fun close() {
            BN_free(bne)
        }

    }
}
