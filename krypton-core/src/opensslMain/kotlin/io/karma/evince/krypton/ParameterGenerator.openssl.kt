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

import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.internal.openssl.*
import io.karma.evince.krypton.key.DHKeyPairGeneratorParameters
import io.karma.evince.krypton.key.KeyPairGeneratorParameters
import io.karma.evince.krypton.utils.WithFree
import io.karma.evince.krypton.utils.checkNotNull
import io.karma.evince.krypton.utils.toBigInteger
import io.karma.evince.krypton.utils.withFreeWithException
import kotlinx.cinterop.*

/**
 * @author Cedric Hammes
 * @since  18/09/2024
 */
@OptIn(InternalKryptonAPI::class)
actual class ParameterGenerator actual constructor(
    algorithm: String,
    private val parameters: ParameterGeneratorParameters
) {
    private val generatorFunction: (ParameterGeneratorParameters) -> KeyPairGeneratorParameters =
        requireNotNull(INTERNAL_FACTORIES[algorithm])
    
    actual constructor(algorithm: Algorithm, parameters: ParameterGeneratorParameters) :
            this(algorithm.checkScopeOrError(Algorithm.Scope.PARAMETER_GENERATOR).toString(), parameters)
    
    actual fun generate(): KeyPairGeneratorParameters = generatorFunction(parameters)
    
    companion object {
        /** @suppress **/
        @InternalKryptonAPI
        private val _INTERNAL_FACTORIES: MutableMap<String, (ParameterGeneratorParameters) -> KeyPairGeneratorParameters> =
            mutableMapOf()
        
        /**
         * This field maps algorithm names to a parameter generation function which takes the parameter generation
         * parameters as input.
         *
         * @author Cedric Hammes
         * @since  26/09/2024
         */
        @InternalKryptonAPI
        val INTERNAL_FACTORIES: Map<String, (ParameterGeneratorParameters) -> KeyPairGeneratorParameters>
            get() = _INTERNAL_FACTORIES
        
        /**
         * This constructor registers the default generator for DH into the list of internal factories.
         *
         * @author Cedric Hammes
         * @since  26/09/2024
         */
        init {
            registerInternalGenerator(Algorithm.DH, nidParameterGenerator(
                nid = EVP_PKEY_DH,
                configurator = { generator, parameters ->
                    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(generator, parameters.bits) != 1)
                        throw RuntimeException("Unable to set prime length")
                },
                outputFactory = { rawParameters, parameters ->
                    val dhParameters = EVP_PKEY_get1_DH(rawParameters).checkNotNull().freeAfter(::DH_free)
                    DHKeyPairGeneratorParameters(
                        DH_get0_p(dhParameters).checkNotNull().toBigInteger(),
                        DH_get0_g(dhParameters).checkNotNull().toBigInteger(),
                        parameters.bits
                    )
                }
            ))
        }
        
        /**
         * This function registers an internal parameter generator for the specified algorithm if the scope list of the
         * algorithm contains the 'parameter generator' scope.
         *
         * @param algorithm The algorithm to register the keypair generator for
         * @param generator The generator itself
         *
         * @author Cedric Hammes
         * @since  26/09/2024
         */
        @InternalKryptonAPI
        fun registerInternalGenerator(
            algorithm: Algorithm,
            generator: (ParameterGeneratorParameters) -> KeyPairGeneratorParameters
        ) {
            algorithm.checkScopeOrError(Algorithm.Scope.PARAMETER_GENERATOR)
            if (INTERNAL_FACTORIES.containsKey(algorithm.name))
                throw RuntimeException("Generator for algorithm '$algorithm' is already registered")
            _INTERNAL_FACTORIES[algorithm.name] = generator
        }
    }
}

/**
 * This function allows a developer to create a parameter generation function based on the algorithm on the specified
 * algorithm as NID. This procedure is based on the OpenSSL EVP_PKEY API. You can configure the context after the
 * initialization and convert the output EVP_PKEY to more Krypton-like parameters.
 *
 * @author Cedric Hammes
 * @since  26/09/2024
 */
@InternalKryptonAPI
fun nidParameterGenerator(
    nid: Int,
    configurator: (CPointer<EVP_PKEY_CTX>, ParameterGeneratorParameters) -> Unit,
    outputFactory: WithFree.(CPointer<EVP_PKEY>, ParameterGeneratorParameters) -> KeyPairGeneratorParameters
): (ParameterGeneratorParameters) -> KeyPairGeneratorParameters = { parameters ->
    withFreeWithException {
        val parameterGenerator = EVP_PKEY_CTX_new_id(nid, null).checkNotNull()
        if (EVP_PKEY_paramgen_init(parameterGenerator) != 1)
            throw RuntimeException("Unable to initialize parameter generator")
        configurator(parameterGenerator, parameters)
        
        memScoped {
            val parametersPtr = allocPointerTo<EVP_PKEY>()
            if (EVP_PKEY_paramgen(parameterGenerator, parametersPtr.ptr) != 1)
                throw RuntimeException("Unable to generate parameters")
            outputFactory(parametersPtr.value.checkNotNull(), parameters)
        }
    }
}
