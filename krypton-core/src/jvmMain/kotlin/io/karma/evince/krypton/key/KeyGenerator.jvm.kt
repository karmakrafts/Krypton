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
import javax.crypto.KeyGenerator

actual class KeyGenerator actual constructor(algorithm: String, parameter: KeyGeneratorParameter) {
    private val keyGenerator: KeyGenerator = KeyGenerator.getInstance(algorithm)
    
    actual constructor(algorithm: Algorithm, parameter: KeyGeneratorParameter) :
            this(algorithm.checkScopeOrError(Algorithm.Scope.KEY_GENERATOR).toString(), parameter)
    
    init {
        this.keyGenerator.init(parameter.size)
    }
    
    actual fun generate(): Key = Key(KeyType.SYMMETRIC, keyGenerator.generateKey())
}
