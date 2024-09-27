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
import io.karma.evince.krypton.GenerationException
import io.karma.evince.krypton.InitializationException
import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.annotations.UncheckedKryptonAPI
import io.karma.evince.krypton.annotations.UnstableKryptonAPI
import io.karma.evince.krypton.ec.EllipticCurve
import io.karma.evince.krypton.internal.openssl.*
import io.karma.evince.krypton.utils.*
import kotlinx.cinterop.*

actual class KeyPairGenerator @UncheckedKryptonAPI actual constructor(
    algorithm: String,
    private val parameters: KeyPairGeneratorParameters
) {
    private val generatorFunction: (KeyPairGeneratorParameters) -> KeyPair =
        requireNotNull(INTERNAL_FACTORIES[algorithm])
    
    actual constructor(algorithm: Algorithm, parameters: KeyPairGeneratorParameters) :
            this(algorithm.validOrError(Algorithm.Scope.KEYPAIR_GENERATOR).toString(), parameters)
    
    actual fun generate(): KeyPair = generatorFunction(parameters)
    
    companion object {
        /** @suppress **/
        @InternalKryptonAPI
        private val _INTERNAL_FACTORIES: MutableMap<String, (KeyPairGeneratorParameters) -> KeyPair> = mutableMapOf()
        
        /**
         * This field maps algorithm names to a keypair generation function which takes the keypair generator parameters
         * as input.
         *
         * @author Cedric Hammes
         * @since  26/09/2024
         */
        @InternalKryptonAPI
        val INTERNAL_FACTORIES: Map<String, (KeyPairGeneratorParameters) -> KeyPair>
            get() = _INTERNAL_FACTORIES
        
        /**
         * This constructor registers the default generators for RSA, ECDH and DH into the list of internal
         * factories.
         *
         * @author Cedric Hammes
         * @since  26/09/2024
         */
        init {
            registerInternalGenerator(Algorithm.RSA, nidKeyPairGenerator<KeyPairGeneratorParameters>(
                nid = EVP_PKEY_RSA,
                algorithm = "RSA",
                contextConfigurator = { context, parameters ->
                    if (EVP_PKEY_CTX_set_rsa_keygen_bits(context, parameters.size) != 1) {
                        throw InitializationException(
                            message = "Unable to set key bits for keypair generator",
                            cause = ErrorHelper.createOpenSSLException()
                        )
                    }
                }
            ))
            registerInternalGenerator(Algorithm.ECDH, ecKeyPairGenerator("ECDH"))
            @OptIn(UnstableKryptonAPI::class)
            registerInternalGenerator(Algorithm.ECDSA, ecKeyPairGenerator("ECDSA"))
            registerInternalGenerator(Algorithm.DH, rawKeyPairGenerator<DHKeyPairGeneratorParameters>(
                algorithm = "DH",
                contextGenerator = { parameters ->
                    val dh = DH_new().checkNotNull().freeAfter(::DH_free)
                    val prime = parameters.p.toOpenSSLBigNumber().checkNotNull()
                    val generator = parameters.g.toOpenSSLBigNumber().checkNotNull()
                    if (DH_set0_pqg(dh, prime, null, generator) != 1) {
                        throw RuntimeException(
                            message = "Unable to initialize prime and generator parameter",
                            cause = ErrorHelper.createOpenSSLException()
                        )
                    }
                    
                    val keyGeneratorParameters = EVP_PKEY_new().checkNotNull()
                    if (EVP_PKEY_set1_DH(keyGeneratorParameters, dh) != 1) {
                        throw RuntimeException(
                            message = "Unable to apply DH parameters to keypair generator",
                            cause = ErrorHelper.createOpenSSLException()
                        )
                    }
                    
                    EVP_PKEY_CTX_new(keyGeneratorParameters, null)
                },
                contextConfigurator = { _, _ -> }
            ))
        }
        
        /**
         * This function registers an internal keypair generator for the specified algorithm if the scope list of the
         * algorithm contains the 'keypair generator' scope.
         *
         * @param algorithm The algorithm to register the keypair generator for
         * @param generator The generator itself
         *
         * @author Cedric Hammes
         * @since  26/09/2024
         */
        @InternalKryptonAPI
        fun registerInternalGenerator(algorithm: Algorithm, generator: (KeyPairGeneratorParameters) -> KeyPair) {
            algorithm.validOrError(Algorithm.Scope.KEYPAIR_GENERATOR)
            registerInternalGenerator(algorithm.toString(), generator)
        }
        
        /**
         * This function registers an internal keypair generator for the specified algorithm.
         *
         * @param algorithm The algorithm to register the keypair generator for
         * @param generator The generator itself
         *
         * @author Cedric Hammes
         * @since  26/09/2024
         */
        @InternalKryptonAPI
        fun registerInternalGenerator(algorithm: String, generator: (KeyPairGeneratorParameters) -> KeyPair) {
            if (INTERNAL_FACTORIES.containsKey(algorithm))
                throw RuntimeException("Generator for algorithm '$algorithm' is already registered")
            _INTERNAL_FACTORIES[algorithm] = generator
        }
    }
}

/**
 * This function allows a developer to create a keypair generation function based on the specified algorithm based on
 * the OpenSSL EVP_PKEY API. You can create the key generation context and configure the context after the
 * initialization.
 *
 * @param algorithm The target algorithm of this generator
 *
 * @author Cedric Hammes
 * @since  26/09/2024
 */
@InternalKryptonAPI
inline fun <reified P : KeyPairGeneratorParameters> rawKeyPairGenerator(
    algorithm: String,
    crossinline contextGenerator: WithFree.(P) -> CPointer<EVP_PKEY_CTX>?,
    crossinline contextConfigurator: (CPointer<EVP_PKEY_CTX>, P) -> Unit
): (KeyPairGeneratorParameters) -> KeyPair = { parameters ->
    if (parameters !is P) {
        throw InitializationException("Invalid parameter type '${parameters::class.qualifiedName}'")
    }
    
    withFreeWithException {
        val generatorContext = contextGenerator(parameters).checkNotNull().freeAfter(::EVP_PKEY_CTX_free)
        if (EVP_PKEY_keygen_init(generatorContext) != 1) {
            throw InitializationException("Unable to init keypair generator", ErrorHelper.createOpenSSLException())
        }
        contextConfigurator(generatorContext, parameters)
        
        val key = memScoped {
            val keyPointer = allocPointerTo<EVP_PKEY>()
            if (EVP_PKEY_keygen(generatorContext, keyPointer.ptr) != 1) {
                throw GenerationException("Unable to generate private key", ErrorHelper.createOpenSSLException())
            }
            keyPointer.value.checkNotNull()
        }
        
        KeyPair(
            Key(KeyType.PUBLIC, algorithm, key),
            Key(KeyType.PRIVATE, algorithm, EVP_PKEY_dup(key).checkNotNull())
        )
    }
}

/**
 * This function allows a developer to create a keypair generation function based on the specified algorithm name and
 * OpenSSL NID based on the OpenSSL EVP_PKEY API. After the automatic creation of the key generation context, you can
 * configure the generation context.
 *
 * @author Cedric Hammes
 * @since  26/09/2024
 */
@InternalKryptonAPI
inline fun <reified P : KeyPairGeneratorParameters> nidKeyPairGenerator(
    nid: Int,
    algorithm: String,
    crossinline contextConfigurator: (CPointer<EVP_PKEY_CTX>, P) -> Unit
): (KeyPairGeneratorParameters) -> KeyPair = rawKeyPairGenerator(
    algorithm = algorithm,
    contextGenerator = { EVP_PKEY_CTX_new_id(nid, null) },
    contextConfigurator = contextConfigurator
)

/**
 * This function allows the developer to create an elliptic curve specific keypair generation function.
 *
 * @param algorithm The name of the target algorithm
 * @returns         The function closure
 *
 * @author Cedric Hammes
 * @since  27/09/2024
 */
@InternalKryptonAPI
fun ecKeyPairGenerator(algorithm: String) = nidKeyPairGenerator<ECKeyPairGeneratorParameters>(
    nid = EVP_PKEY_EC,
    algorithm = algorithm,
    contextConfigurator = { context, parameters ->
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, parameters.curve.toOpenSSLId()) != 1) {
            throw InitializationException(
                message = "Unable to set curve information for $algorithm generator",
                cause = ErrorHelper.createOpenSSLException()
            )
        }
    }
)

/**
 * This function converts the Elliptic Curve enum to the OpenSSL NID. This function is used by the elliptic curve key
 * pair generator.
 *
 * @author Cedric Hammes
 * @since  26/09/2024
 */
fun EllipticCurve.toOpenSSLId(): Int = when (this) {
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
