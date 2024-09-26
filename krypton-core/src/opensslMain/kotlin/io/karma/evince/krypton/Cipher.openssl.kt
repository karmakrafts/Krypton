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
import io.karma.evince.krypton.internal.cipher.InternalCipher
import io.karma.evince.krypton.internal.cipher.InternalCipherFactoryRegistry
import io.karma.evince.krypton.key.Key

/** @suppress **/
@OptIn(InternalKryptonAPI::class)
actual class Cipher actual constructor(algorithm: String, key: Key, parameters: CipherParameters) : AutoCloseable {
    private val internal: InternalCipher = InternalCipherFactoryRegistry.createCipher(algorithm, key, parameters)
    
    actual constructor(algorithm: Algorithm, key: Key, parameters: CipherParameters) :
            this(algorithm.checkScopeOrError(Algorithm.Scope.CIPHER).toString(), key, parameters.validate(algorithm))
    
    actual fun process(data: ByteArray, aad: ByteArray?): ByteArray = internal.process(data, aad)
    
    actual override fun close(): Unit = internal.close()
    
    actual enum class Mode {
        ENCRYPT, DECRYPT
    }
}
