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
import io.karma.evince.krypton.utils.JavaCryptoHelper
import javax.crypto.KeyGenerator

actual class KeyGenerator actual constructor(algorithm: String, parameter: KeyGeneratorParameter) {
    private val keyGenerator: KeyGenerator

    actual constructor(algorithm: Algorithm, parameter: KeyGeneratorParameter) : this(algorithm.toString(), parameter)

    init {
        if (!JavaCryptoHelper.getAlgorithms<KeyGenerator>().contains(algorithm))
            throw IllegalArgumentException("The algorithm '$algorithm' is not available, the following are officially " +
                    "supported by Krypton: ${Algorithm.entries.filter { !it.asymmetric }.joinToString(", ")}"
            )

        this.keyGenerator = KeyGenerator.getInstance(algorithm)
        this.keyGenerator.init(parameter.size)
    }

    actual fun generate(): Key = Key(KeyType.SYMMETRIC, keyGenerator.generateKey())

}
