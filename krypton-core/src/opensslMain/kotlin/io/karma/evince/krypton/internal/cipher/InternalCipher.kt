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

package io.karma.evince.krypton.internal.cipher

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.CipherParameters
import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.key.Key

/** @suppress **/
@InternalKryptonAPI
interface InternalCipher : AutoCloseable {
    fun process(data: ByteArray, aad: ByteArray?): ByteArray
}

/** @suppress **/
@InternalKryptonAPI
object InternalCipherFactoryRegistry {
    private val generators: MutableMap<String, (Key, CipherParameters) -> InternalCipher> =
        mutableMapOf()
    
    init {
        registerFactory(Algorithm.AES) { key, params -> AESCipher(key, params) }
    }
    
    fun registerFactory(algorithm: String, factory: (Key, CipherParameters) -> InternalCipher) {
        if (generators.containsKey(algorithm))
            throw RuntimeException("Factory for algorithm '$algorithm' is already registered")
        generators[algorithm] = factory
    }
    
    fun registerFactory(algorithm: Algorithm, factory: (Key, CipherParameters) -> InternalCipher) =
        registerFactory(algorithm.toString(), factory)
    
    fun createCipher(algorithm: String, key: Key, parameters: CipherParameters): InternalCipher =
        generators[algorithm]?.invoke(key, parameters) ?: throw NullPointerException("'$algorithm' is not registered")
}
