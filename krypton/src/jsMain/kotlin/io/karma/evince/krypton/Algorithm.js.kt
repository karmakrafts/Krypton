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

import io.karma.evince.krypton.parameters.KeyGeneratorParameters
import js.typedarrays.Uint8Array
import js.typedarrays.toUint8Array
import web.crypto.AesKeyGenParams
import web.crypto.crypto

internal actual class DefaultHashProvider actual constructor(private val algorithm: Algorithm) : Hash {
    override suspend fun hash(input: ByteArray): ByteArray = Uint8Array(crypto.subtle.digest(algorithm.literal, input.toUint8Array()))
        .toByteArray()
}

internal actual class DefaultSymmetricCipher actual constructor(private val algorithm: Algorithm) : KeyGenerator {
    override suspend fun generateKey(parameters: KeyGeneratorParameters): Key = Key(
        algorithm = algorithm,
        type = Key.Type.OTHER,
        usages = parameters.usages,
        internal = crypto.subtle.generateKey(
            algorithm = when(algorithm) {
                DefaultAlgorithm.AES -> AesKeyGenParams.invoke(
                    name = "AES-${parameters.blockMode?: algorithm.defaultBlockMode}",
                    length = parameters.bitSize.toShort())
                else -> throw IllegalArgumentException("Algorithm '$algorithm' is not supported")
            },
            extractable = true,
            keyUsages = parameters.usages.toJsUsages()
        )
    )
}
