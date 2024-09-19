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

package io.karma.evince.krypton.internal.key

import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.ec.EllipticCurve
import io.karma.evince.krypton.key.*
import io.karma.evince.krypton.utils.*
import kotlinx.cinterop.*
import libssl.*

/** @suppress **/
@InternalKryptonAPI
open class OpenSSLKeyPairGenerator<P : KeyPairGeneratorParameters>(
    nid: Int,
    private val algorithm: String,
    parameters: P,
    configurator: (CPointer<EVP_PKEY_CTX>, P) -> Unit
) : InternalKeyPairGenerator {
    private val keyGenerator: CPointer<EVP_PKEY_CTX> = EVP_PKEY_CTX_new_id(nid, null).checkNotNull()
    
    init {
        if (EVP_PKEY_keygen_init(keyGenerator) != 1)
            throw RuntimeException("Unable to initialize parameter generator", ErrorHelper.createOpenSSLException())
        configurator(keyGenerator, parameters)
    }
    
    override fun generate(): KeyPair = withFreeWithException {
        val key = EVP_PKEY_new().checkNotNull().freeAfterOnException(::EVP_PKEY_free)
        memScoped {
            val keyPtr = allocPointerTo<EVP_PKEY>()
            keyPtr.value = key
            if (EVP_PKEY_keygen(keyGenerator, keyPtr.ptr) != 1)
                throw RuntimeException("Unable to generate keypair", ErrorHelper.createOpenSSLException())
        }
        return KeyPair(
            Key(KeyType.PUBLIC, algorithm, key),
            Key(KeyType.PRIVATE, algorithm, EVP_PKEY_dup(key).checkNotNull())
        )
    }
    
    override fun close() {
        EVP_PKEY_CTX_free(keyGenerator)
    }
}

/** @suppress **/
@InternalKryptonAPI
open class ParameterizedOpenSSLKeyPairGenerator(
    parameterGenerator: WithFree.() -> CPointer<EVP_PKEY>,
    private val algorithm: String,
) : InternalKeyPairGenerator {
    private val keyGeneratorParameters: CPointer<EVP_PKEY> = withFree { parameterGenerator() }
    private val keyGenerator: CPointer<EVP_PKEY_CTX> = withFree {
        EVP_PKEY_CTX_new(keyGeneratorParameters, null).checkNotNull()
    }
    
    init {
        if (EVP_PKEY_keygen_init(keyGenerator) != 1)
            throw RuntimeException("Unable to initialize parameter generator", ErrorHelper.createOpenSSLException())
    }
    
    override fun generate(): KeyPair = withFreeWithException {
        val key = EVP_PKEY_new().checkNotNull().freeAfterOnException(::EVP_PKEY_free)
        memScoped {
            val keyPtr = allocPointerTo<EVP_PKEY>()
            keyPtr.value = key
            if (EVP_PKEY_keygen(keyGenerator, keyPtr.ptr) != 1)
                throw RuntimeException("Unable to generate keypair", ErrorHelper.createOpenSSLException())
        }
        
        return KeyPair(
            Key(KeyType.PUBLIC, algorithm, key),
            Key(KeyType.PRIVATE, algorithm, EVP_PKEY_dup(key).checkNotNull())
        )
    }
    
    override fun close() {
        EVP_PKEY_CTX_free(keyGenerator)
        EVP_PKEY_free(keyGeneratorParameters)
    }
}

/** @suppress **/
@InternalKryptonAPI
open class ParameterGeneratingOpenSSLKeyPairGenerator<P : KeyPairGeneratorParameters>(
    nid: Int,
    private val algorithm: String,
    parameters: P,
    configurator: (CPointer<EVP_PKEY_CTX>, P) -> Unit
) : InternalKeyPairGenerator {
    private val parameterGenerator: CPointer<EVP_PKEY_CTX> = EVP_PKEY_CTX_new_id(nid, null).checkNotNull()
    private val generatedParameters: CPointerVar<EVP_PKEY> = nativeHeap.allocPointerTo<EVP_PKEY>().checkNotNull()
    private val keyPairGenerator: CPointer<EVP_PKEY_CTX>
    
    init {
        if (EVP_PKEY_paramgen_init(parameterGenerator) != 1)
            throw RuntimeException("Unable to initialize parameter generator", ErrorHelper.createOpenSSLException())
        configurator(parameterGenerator, parameters)
        if (EVP_PKEY_paramgen(parameterGenerator, generatedParameters.ptr) != 1)
            throw RuntimeException("Unable to generate curve parameters", ErrorHelper.createOpenSSLException())
        
        keyPairGenerator = EVP_PKEY_CTX_new(generatedParameters.value, null).checkNotNull()
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
            Key(KeyType.PUBLIC, algorithm, key),
            Key(KeyType.PRIVATE, algorithm, EVP_PKEY_dup(key).checkNotNull())
        )
    }
    
    override fun close() {
        EVP_PKEY_CTX_free(keyPairGenerator)
        EVP_PKEY_free(generatedParameters.value)
        nativeHeap.free(generatedParameters)
        EVP_PKEY_CTX_free(parameterGenerator)
    }
}

/** @suppress **/
@InternalKryptonAPI
internal class ECKeyPairGenerator(algorithm: String, params: ECKeyPairGeneratorParameters) :
    ParameterGeneratingOpenSSLKeyPairGenerator<ECKeyPairGeneratorParameters>(EVP_PKEY_EC, algorithm, params,
        { parameterGenerator, parameters ->
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(parameterGenerator, parameters.curve.toOpenSSLId()) != 1)
                throw RuntimeException("Unable to set curve to generator", ErrorHelper.createOpenSSLException())
        }
    )

/** @suppress **/
@InternalKryptonAPI
internal class RSAKeyPairGenerator(params: KeyPairGeneratorParameters) :
    OpenSSLKeyPairGenerator<KeyPairGeneratorParameters>(EVP_PKEY_RSA, "RSA", params,
        { keyGenerator, parameters ->
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(keyGenerator, parameters.size) != 1)
                throw RuntimeException("Unable to set RSA modulus", ErrorHelper.createOpenSSLException())
        }
    )

/** @suppress **/
@InternalKryptonAPI
internal class ParameterizedDHKeyPairGenerator(parameters: DHKeyPairGeneratorParameters) :
    ParameterizedOpenSSLKeyPairGenerator(
        {
            val dh = DH_new().checkNotNull().freeAfter(::DH_free)
            val prime = parameters.p.toOpenSSLBigNumber().checkNotNull()
            val generator = parameters.g.toOpenSSLBigNumber().checkNotNull()
            if (DH_set0_pqg(dh, prime, null, generator) != 1)
                throw RuntimeException("Unable to set parameters", ErrorHelper.createOpenSSLException())
            
            val keyGeneratorParameters = EVP_PKEY_new().checkNotNull()
            if (EVP_PKEY_set1_DH(keyGeneratorParameters, dh) != 1)
                throw RuntimeException("Unable to apply parameters", ErrorHelper.createOpenSSLException())
            keyGeneratorParameters
        },
        "DH"
    )

/** @suppress **/
@InternalKryptonAPI
internal class DefaultDHKeyPairGenerator(params: KeyPairGeneratorParameters) :
    ParameterGeneratingOpenSSLKeyPairGenerator<KeyPairGeneratorParameters>(EVP_PKEY_DH, "DH", params,
        { parameterGenerator, parameters ->
            if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(parameterGenerator, parameters.size) != 1)
                throw RuntimeException("Unable to set prime length", ErrorHelper.createOpenSSLException())
        }
    )

// TODO: Add implementation for custom generator value + custom prime (validate prime against specified length)

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
