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
import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.key.internal.DefaultDHKeyPairGenerator
import io.karma.evince.krypton.key.internal.ECKeyPairGenerator
import io.karma.evince.krypton.key.internal.InternalKeyPairGenerator
import io.karma.evince.krypton.key.internal.RSAKeyPairGenerator

@OptIn(InternalKryptonAPI::class)
actual class KeyPairGenerator actual constructor(
    algorithm: String,
    parameter: KeyPairGeneratorParameter
) : AutoCloseable {
    private val keyPairGeneratorImpl: InternalKeyPairGenerator = when (algorithm) {
        "RSA" -> RSAKeyPairGenerator(parameter)
        "ECDH" -> ECKeyPairGenerator(Algorithm.ECDH, parameter as ECKeyPairGeneratorParameter)
        "DH" -> DefaultDHKeyPairGenerator(parameter)
        else -> throw IllegalArgumentException("Algorithm '$algorithm' is not supported")
    }

    actual constructor(algorithm: Algorithm, parameter: KeyPairGeneratorParameter) :
            this(algorithm.checkScopeOrError(Algorithm.Scope.KEYPAIR_GENERATOR).toString(), parameter)

    actual fun generate(): KeyPair = this.keyPairGeneratorImpl.generate()
    actual override fun close() {
        this.keyPairGeneratorImpl.close()
    }
}
