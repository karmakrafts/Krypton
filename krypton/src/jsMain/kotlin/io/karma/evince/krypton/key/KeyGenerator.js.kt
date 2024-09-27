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
import io.karma.evince.krypton.PlatformHelper
import io.karma.evince.krypton.annotations.UncheckedKryptonAPI
import web.crypto.AesKeyGenParams
import web.crypto.KeyUsage
import web.crypto.crypto

/**
 * @author Cedric Hammes
 * @since  27/09/2024
 * @suppress
 */
actual class KeyGenerator @UncheckedKryptonAPI actual constructor(
    private val algorithm: String,
    private val parameters: KeyGeneratorParameters
) {
    actual constructor(algorithm: Algorithm, parameters: KeyGeneratorParameters) :
            this(algorithm.checkScopeOrError(Algorithm.Scope.KEY_GENERATOR).toString(), parameters)

    actual suspend fun generate(): Key = if (PlatformHelper.IS_BROWSER) {
        when(algorithm) {
            "AES" -> Key(
                algorithm = algorithm,
                type = KeyType.SYMMETRIC,
                body = Key.KeyBody.BrowserKeyBody(crypto.subtle.generateKey(
                    algorithm = AesKeyGenParams.invoke(
                        name = "AES-${parameters.blockMode?: Algorithm.AES.defaultBlockMode}",
                        length = parameters.size.toShort()
                    ),
                    extractable = false, // Can be extracted in ie. exportKey
                    arrayOf(KeyUsage.decrypt, KeyUsage.encrypt)
                ))
            )
            else -> throw IllegalArgumentException("Algorithm '$algorithm' is not supported")
        }
    } else {
        Key(
            algorithm = algorithm,
            type = KeyType.SYMMETRIC,
            body = Key.KeyBody.NodeKeyBody(node.crypto.randomBytes(parameters.size / 8))
        )
    }
}
