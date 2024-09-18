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

package io.karma.evince.krypton.key.internal

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.key.ECKeyPairGeneratorParameter
import io.karma.evince.krypton.key.KeyPair
import io.karma.evince.krypton.key.KeyPairGeneratorParameter

/** @suppress **/
@InternalKryptonAPI
interface InternalKeyPairGenerator {
    
    fun generate(): KeyPair
    fun close()
}

/** @suppress **/
@InternalKryptonAPI
object InternalKeyPairGeneratorRegistry {
    
    private val generators: MutableMap<String, (KeyPairGeneratorParameter) -> InternalKeyPairGenerator> = mutableMapOf()
    
    init {
        this.registerFactory(Algorithm.RSA) { parameters -> RSAKeyPairGenerator(parameters) }
        this.registerFactory(Algorithm.DH) { parameters -> DefaultDHKeyPairGenerator(parameters) }
        this.registerFactory(Algorithm.ECDH) { parameters ->
            ECKeyPairGenerator("ECDH", parameters as ECKeyPairGeneratorParameter)
        }
    }
    
    fun registerFactory(algorithm: String, factory: (KeyPairGeneratorParameter) -> InternalKeyPairGenerator) {
        if (generators.containsKey(algorithm)) throw RuntimeException("Factory for algorithm '$algorithm' is already registered")
        generators[algorithm] = factory
    }
    
    fun registerFactory(algorithm: Algorithm, factory: (KeyPairGeneratorParameter) -> InternalKeyPairGenerator) =
        this.registerFactory(algorithm.toString(), factory)
    
    fun createGenerator(algorithm: String, parameters: KeyPairGeneratorParameter): InternalKeyPairGenerator =
        generators[algorithm]?.invoke(parameters) ?: throw NullPointerException("'$algorithm' is not registered")
}
