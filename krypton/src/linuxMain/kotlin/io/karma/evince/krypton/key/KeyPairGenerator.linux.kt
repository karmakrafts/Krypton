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

        // openssl ecparam -name <curve name> -out elliptic-curve-parameters.pem
        // openssl ecparam -in elliptic-curve-parameters.pem -genkey -noout -out private-key.pem
        // openssl ec -in private-key.pem -pubout -out public-key.pem

        // TODO: I think this can be improved to remove the copy but I couldn't find a good and beautiful solution
        private val curve: CPointer<EC_GROUP> = when (val curve = parameter.ellipticCurve) {
            is ParameterizedEllipticCurve -> requireNotNull(EC_GROUP_dup(curve.curve))
            is DefaultEllipticCurve -> requireNotNull(EC_GROUP_new_by_curve_name(curve.toOpenSSLId()))
            else -> throw UnsupportedOperationException("Unsupported elliptic curve class type '$curve")
        }

        override fun generate(): KeyPair {
            // Generate private key
            val privateEcKey = requireNotNull(EC_KEY_new())
            if (EC_KEY_set_group(privateEcKey, curve) != 1) {
                EC_KEY_free(privateEcKey)
                throw RuntimeException("Unable to apply curve to key", ErrorHelper.createOpenSSLException())
            }

            if (EC_KEY_generate_key(privateEcKey) != 1) {
                EC_KEY_free(privateEcKey)
                throw RuntimeException("Unable to generate keypair", ErrorHelper.createOpenSSLException())
            }

            // Get public key to private key
            val publicEcKey = requireNotNull(EC_KEY_new())
            if (EC_KEY_set_group(publicEcKey, curve) != 1) {
                EC_KEY_free(publicEcKey)
                EC_KEY_free(privateEcKey)
                throw RuntimeException("Unable to apply curve to key", ErrorHelper.createOpenSSLException())
            }

            if (EC_KEY_set_public_key(publicEcKey, EC_KEY_get0_public_key(privateEcKey)) != 1) {
                EC_KEY_free(publicEcKey)
                EC_KEY_free(privateEcKey)
                throw RuntimeException("Unable to acquire public key", ErrorHelper.createOpenSSLException())
            }

            // Convert EC keys to EVP_PKEYs
            val privateKey = requireNotNull(EVP_PKEY_new())
            if (EVP_PKEY_assign(privateKey, EVP_PKEY_EC, privateEcKey) != 1) {
                EVP_PKEY_free(privateKey)
                EC_KEY_free(publicEcKey)
                EC_KEY_free(privateEcKey)
                throw RuntimeException(
                    "Unable to convert private EC key to EVP key",
                    ErrorHelper.createOpenSSLException()
                )
            }

            val publicKey = requireNotNull(EVP_PKEY_new())
            if (EVP_PKEY_assign(publicKey, EVP_PKEY_EC, publicEcKey) != 1) {
                EVP_PKEY_free(publicKey)
                EVP_PKEY_free(privateKey)
                EC_KEY_free(publicEcKey)
                EC_KEY_free(privateEcKey)
                throw RuntimeException(
                    "Unable to convert public EC key to EVP key",
                    ErrorHelper.createOpenSSLException()
                )
            }

            EC_KEY_free(publicEcKey)
            EC_KEY_free(privateEcKey)
            return KeyPair(Key(KeyType.PUBLIC, "ECDH", publicKey), Key(KeyType.PRIVATE, "ECDH", privateKey))
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
