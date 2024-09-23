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

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.key.DHKeyPairGeneratorParameters
import io.karma.evince.krypton.key.ECKeyPairGeneratorParameters
import io.karma.evince.krypton.key.KeyPair
import io.karma.evince.krypton.key.KeyPairGeneratorParameters

/** @suppress **/
@InternalKryptonAPI
interface InternalKeyPairGenerator : AutoCloseable {
    fun generate(): KeyPair
}

/** @suppress **/
@InternalKryptonAPI
object InternalKeyPairGeneratorRegistry {
    private val generators: MutableMap<String, (KeyPairGeneratorParameters) -> InternalKeyPairGenerator> =
        mutableMapOf()
    
    init {
        registerFactory(Algorithm.RSA) { parameters -> RSAKeyPairGenerator(parameters) }
        registerFactory(Algorithm.DH) { parameters ->
            when(parameters) {
                is DHKeyPairGeneratorParameters -> ParameterizedDHKeyPairGenerator(parameters)
                else -> DefaultDHKeyPairGenerator(parameters)
            }
        }
        registerFactory(Algorithm.ECDH) { parameters ->
            ECKeyPairGenerator("ECDH", parameters as ECKeyPairGeneratorParameters)
        }
    }
    
    fun registerFactory(algorithm: String, factory: (KeyPairGeneratorParameters) -> InternalKeyPairGenerator) {
        if (generators.containsKey(algorithm))
            throw RuntimeException("Factory for algorithm '$algorithm' is already registered")
        generators[algorithm] = factory
    }
    
    fun registerFactory(algorithm: Algorithm, factory: (KeyPairGeneratorParameters) -> InternalKeyPairGenerator) =
        registerFactory(algorithm.toString(), factory)
    
    fun createGenerator(algorithm: String, parameters: KeyPairGeneratorParameters): InternalKeyPairGenerator =
        generators[algorithm]?.invoke(parameters) ?: throw NullPointerException("'$algorithm' is not registered")
}
