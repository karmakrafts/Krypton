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
import io.karma.evince.krypton.ec.EllipticCurve
import io.karma.evince.krypton.utils.ErrorHelper
import io.karma.evince.krypton.utils.checkNotNull
import io.karma.evince.krypton.utils.withFreeWithException
import kotlinx.cinterop.*
import libssl.*

// TODO: Implement internal keypair generator interface (platform-specific) to allow separation of post-quantum
//  cryptography API into a separate module

actual class KeyPairGenerator actual constructor(
    algorithm: String,
    parameter: KeyPairGeneratorParameter
) : AutoCloseable {
    private val keyPairGeneratorImpl: KeyPairGeneratorImpl = when (algorithm) {
        "RSA" -> RSAKeyPairGeneratorImpl(parameter)
        "ECDH" -> ECKeyPairGeneratorImpl(Algorithm.ECDH, parameter as ECKeyPairGeneratorParameter)
        "DH" -> DHKeyPairGeneratorImpl(parameter)
        else -> throw IllegalArgumentException("Algorithm '$algorithm' is not supported")
    }

    actual constructor(algorithm: Algorithm, parameter: KeyPairGeneratorParameter) :
            this(algorithm.checkScopeOrError(Algorithm.Scope.KEYPAIR_GENERATOR).toString(), parameter)

    actual fun generate(): KeyPair = this.keyPairGeneratorImpl.generate()
    actual override fun close() {
        this.keyPairGeneratorImpl.close()
    }

    interface KeyPairGeneratorImpl {
        fun generate(): KeyPair
        fun close()
    }

    internal class DHKeyPairGeneratorImpl(parameter: KeyPairGeneratorParameter) : KeyPairGeneratorImpl {
        override fun generate(): KeyPair = TODO()
        override fun close() {}
    }

    internal class ECKeyPairGeneratorImpl(
        private val algorithm: Algorithm,
        parameter: ECKeyPairGeneratorParameter
    ) : KeyPairGeneratorImpl {
        private val parameterGenerator: CPointer<EVP_PKEY_CTX> = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, null).checkNotNull()
        private val curveParameters: CPointerVar<EVP_PKEY> = nativeHeap.allocPointerTo<EVP_PKEY>().checkNotNull()
        private val keyPairGenerator: CPointer<EVP_PKEY_CTX>

        init {
            if (EVP_PKEY_paramgen_init(parameterGenerator) != 1)
                throw RuntimeException("Unable to initialize parameter generator", ErrorHelper.createOpenSSLException())
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(parameterGenerator, parameter.curve.toOpenSSLId()) != 1)
                throw RuntimeException("Unable to set curve to generator", ErrorHelper.createOpenSSLException())
            if (EVP_PKEY_paramgen(parameterGenerator, curveParameters.ptr) != 1)
                throw RuntimeException("Unable to generate curve parameters", ErrorHelper.createOpenSSLException())

            keyPairGenerator = EVP_PKEY_CTX_new(curveParameters.value, null).checkNotNull()
            if (EVP_PKEY_keygen_init(keyPairGenerator) != 1)
                throw RuntimeException("Unable to initialize keypair generator", ErrorHelper.createOpenSSLException())
        }

        override fun generate(): KeyPair = withFreeWithException {
            val key = EVP_PKEY_new().checkNotNull().freeAfterOnException(::EVP_PKEY_free)
            memScoped {
                val keyPtr = allocPointerTo<EVP_PKEY>()
                keyPtr.value = key
                if (EVP_PKEY_keygen(keyPairGenerator, keyPtr.ptr) != 1)
                    throw RuntimeException("Unable to generate keypair", ErrorHelper.createOpenSSLException())
            }
            return KeyPair(
                Key(KeyType.PUBLIC, algorithm.toString(), key),
                Key(KeyType.PRIVATE, algorithm.toString(), EVP_PKEY_dup(key).checkNotNull())
            )
        }

        override fun close() {
            EVP_PKEY_CTX_free(keyPairGenerator)
            EVP_PKEY_free(curveParameters.value)
            nativeHeap.free(curveParameters)
            EVP_PKEY_CTX_free(parameterGenerator)
        }
    }

    internal class RSAKeyPairGeneratorImpl(parameter: KeyPairGeneratorParameter) : KeyPairGeneratorImpl {
        private var generationContext = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, null).checkNotNull()

        init {
            if (EVP_PKEY_keygen_init(generationContext) != 1)
                throw RuntimeException("Unable to initialize key generator", ErrorHelper.createOpenSSLException())
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(generationContext, parameter.size) != 1)
                throw RuntimeException("Unable to set RSA modulus", ErrorHelper.createOpenSSLException())
        }

        override fun generate(): KeyPair = withFreeWithException {
            val key = EVP_PKEY_new().checkNotNull().freeAfterOnException(::EVP_PKEY_free)
            memScoped {
                val keyPtr = allocPointerTo<EVP_PKEY>()
                keyPtr.value = key
                if (EVP_PKEY_keygen(generationContext, keyPtr.ptr) != 1)
                    throw RuntimeException("Unable to generate keypair", ErrorHelper.createOpenSSLException())
            }
            return KeyPair(
                Key(KeyType.PUBLIC, "RSA", key),
                Key(KeyType.PRIVATE, "RSA", EVP_PKEY_dup(key).checkNotNull())
            )
        }

        override fun close() { // TODO: Warum bekomme ich hier einen Segfault
            EVP_PKEY_CTX_free(generationContext)
        }
    }
}

private fun EllipticCurve.toOpenSSLId(): Int = when (this) {
    EllipticCurve.PRIME192V1 -> NID_X9_62_prime192v1
    EllipticCurve.PRIME192V2 -> NID_X9_62_prime192v2
    EllipticCurve.PRIME192V3 -> NID_X9_62_prime192v3
    EllipticCurve.PRIME239V1 -> NID_X9_62_prime239v1
    EllipticCurve.PRIME239V2 -> NID_X9_62_prime239v2
    EllipticCurve.PRIME239V3 -> NID_X9_62_prime192v3
    EllipticCurve.PRIME256V1 -> NID_X9_62_prime256v1
    EllipticCurve.BRAINPOOL_P160T1 -> NID_brainpoolP160t1
    EllipticCurve.BRAINPOOL_P192T1 -> NID_brainpoolP192t1
    EllipticCurve.BRAINPOOL_P224T1 -> NID_brainpoolP224t1
    EllipticCurve.BRAINPOOL_P256T1 -> NID_brainpoolP256t1
    EllipticCurve.BRAINPOOL_P320T1 -> NID_brainpoolP320t1
    EllipticCurve.BRAINPOOL_P384T1 -> NID_brainpoolP384t1
    EllipticCurve.BRAINPOOL_P512T1 -> NID_brainpoolP512t1
    EllipticCurve.BRAINPOOL_P160R1 -> NID_brainpoolP160r1
    EllipticCurve.BRAINPOOL_P192R1 -> NID_brainpoolP192r1
    EllipticCurve.BRAINPOOL_P256R1 -> NID_brainpoolP256r1
    EllipticCurve.BRAINPOOL_P224R1 -> NID_brainpoolP224r1
    EllipticCurve.BRAINPOOL_P320R1 -> NID_brainpoolP320r1
    EllipticCurve.BRAINPOOL_P384R1 -> NID_brainpoolP384r1
    EllipticCurve.BRAINPOOL_P512R1 -> NID_brainpoolP512r1
}
