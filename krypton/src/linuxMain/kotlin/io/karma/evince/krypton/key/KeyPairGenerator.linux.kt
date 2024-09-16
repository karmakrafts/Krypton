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
import io.karma.evince.krypton.ec.ParameterizedEllipticCurve
import io.karma.evince.krypton.ec.toOpenSSLId
import io.karma.evince.krypton.utils.ErrorHelper
import kotlinx.cinterop.*
import libssl.*

// TODO: Implement internal keypair generator interface (platform-specific) to allow separation of post-quantum
//  cryptography API into a separate module

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
        // TODO: I think this can be improved to remove the copy but I couldn't find a good and beautiful solution
        private val curve: CPointer<EC_GROUP> = when (val curve = parameter.ellipticCurve) {
            is ParameterizedEllipticCurve -> requireNotNull(EC_GROUP_dup(curve.curve))
            is DefaultEllipticCurve -> requireNotNull(EC_GROUP_new_by_curve_name(curve.toOpenSSLId()))
            else -> throw UnsupportedOperationException("Unsupported elliptic curve class type '$curve")
        }

        override fun generate(): KeyPair {
            val ellipticCurveKey = requireNotNull(EC_KEY_new())
            if (EC_KEY_set_group(ellipticCurveKey, curve) != 1) {
                throw RuntimeException("Unable to assign curve", ErrorHelper.createOpenSSLException())
            }

            val privateKey = requireNotNull(EVP_PKEY_new())
            if (EVP_PKEY_assign(privateKey, EVP_PKEY_EC, ellipticCurveKey) != 1) {
                throw RuntimeException("Unable to assign EC key to EVP_PKEY", ErrorHelper.createOpenSSLException())
            }

            val keyGeneratorContext = requireNotNull(EVP_PKEY_CTX_new(privateKey, null))
            if (EVP_PKEY_keygen_init(keyGeneratorContext) != 1) {
                throw RuntimeException("Unable to initialize key generator", ErrorHelper.createOpenSSLException())
            }
            memScoped {
                val pointerToKeyPointer = allocPointerTo<EVP_PKEY>()
                pointerToKeyPointer.value = privateKey
                if (EVP_PKEY_keygen(keyGeneratorContext, pointerToKeyPointer.ptr) != 1) {
                    throw RuntimeException("Unable to generate key", ErrorHelper.createOpenSSLException())
                }
            }

            if (EVP_PKEY_check(keyGeneratorContext) != 1)
                throw RuntimeException("Key generator produced invalid results", ErrorHelper.createOpenSSLException())

            return KeyPair(
                Key(KeyType.PUBLIC, "ECDH", privateKey),
                Key(KeyType.PRIVATE, "ECDH", requireNotNull(EVP_PKEY_dup(privateKey)))
            )
        }

        override fun close() {
            EC_GROUP_free(curve)
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
