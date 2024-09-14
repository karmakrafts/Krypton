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
import io.karma.evince.krypton.ec.DefaultEllipticCurve
import io.karma.evince.krypton.ec.toOpenSSLId
import io.karma.evince.krypton.utils.ErrorHelper
import kotlinx.cinterop.*
import libssl.*

actual class KeyPairGenerator actual constructor(
    algorithm: Algorithm,
    parameter: KeyPairGeneratorParameter
) : AutoCloseable {
    private val keyPairGeneratorImpl: KeyPairGeneratorImpl = when (algorithm) {
        Algorithm.RSA -> RSAKeyPairGeneratorImpl(parameter)
        Algorithm.ECDH -> ECDHKeyPairGeneratorImpl(parameter as ECKeyPairGeneratorParameter)
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

    internal class ECDHKeyPairGeneratorImpl(parameter: ECKeyPairGeneratorParameter) : KeyPairGeneratorImpl {
        private val parameterGeneratorContext: CPointer<EVP_PKEY_CTX>? = requireNotNull(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, null))

        init {
            if (EVP_PKEY_paramgen_init(parameterGeneratorContext) != 1)
                throw RuntimeException("Unable to initialize parameter generator", ErrorHelper.createOpenSSLException())

            // TODO: Handle non-default elliptic curves
            when (val curve = parameter.ellipticCurve) {
                is DefaultEllipticCurve -> {
                    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(parameterGeneratorContext, curve.toOpenSSLId()) != 1)
                        throw RuntimeException("Unable to set curve to '$curve'", ErrorHelper.createOpenSSLException())
                }
                else -> throw IllegalArgumentException("Unsupported elliptic curve type '${curve::class.qualifiedName}'")
            }
        }

        override fun generate(): KeyPair = memScoped {
            val parameters = allocPointerTo<EVP_PKEY>()
            if (EVP_PKEY_paramgen(parameterGeneratorContext, parameters.ptr) != 1)
                throw RuntimeException("Unable to generate parameters", ErrorHelper.createOpenSSLException())

            val keyGeneratorContext = requireNotNull(EVP_PKEY_CTX_new(parameters.value, null))
            if (EVP_PKEY_keygen_init(keyGeneratorContext) != 1)
                throw RuntimeException("Unable to initialize key generator", ErrorHelper.createOpenSSLException())

            val keyPair = allocPointerTo<EVP_PKEY>()
            if (EVP_PKEY_keygen(keyGeneratorContext, keyPair.ptr) != 1) {
                EVP_PKEY_CTX_free(keyGeneratorContext)
                throw RuntimeException("Unable to generate private key", ErrorHelper.createOpenSSLException())
            }

            // Convert to EC Keys TODO: How to get EC public and private key

            // Free resources
            EVP_PKEY_CTX_free(keyGeneratorContext)
            EVP_PKEY_free(parameters.value)
            EVP_PKEY_free(keyPair.value)

            // Return
            // return KeyPair(Key(KeyType.PUBLIC, "ECDH", publicKey), Key(KeyType.PRIVATE, "ECDH", privateKey))
            TODO()
        }

        override fun close() {
            if (parameterGeneratorContext != null)
                EVP_PKEY_CTX_free(parameterGeneratorContext)
        }
    }

    internal class RSAKeyPairGeneratorImpl(private val parameter: KeyPairGeneratorParameter) : KeyPairGeneratorImpl {
        private var bne: CPointer<BIGNUM>? = BN_new()

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
            if (bne != null)
                BN_free(bne)
        }

    }
}
