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
import io.karma.evince.krypton.annotations.UncheckedKryptonAPI
import web.crypto.AesKeyGenParams
import web.crypto.KeyUsage
import web.crypto.crypto

/**
 * This is the JS-only implementation for the key-generation with Krypton. This API uses the Web Cryptography API which was specified by the
 * W3C.
 *
 * @author Cedric Hammes
 * @since  28/09/2024
 *
 * @see [AES-CBC, Web Cryptography API Examples](https://github.com/diafygi/webcrypto-examples?tab=readme-ov-file#aes-cbc---generatekey)
 * @see [Web Cryptography API, W3C](https://w3c.github.io/webcrypto/#crypto-interface)
 */
actual class KeyGenerator @UncheckedKryptonAPI actual constructor(
    private val algorithm: String,
    private val parameters: KeyGeneratorParameters
) {
    actual constructor(algorithm: Algorithm, parameters: KeyGeneratorParameters) :
            this(algorithm.validOrError(Algorithm.Scope.KEY_GENERATOR).toString(), parameters)

    /**
     * This function generates a private key and derives the public key from the private key. These operations are done
     * in the backend and the backend-internal structure is wrapped into a key.
     *
     * @author Cedric Hammes
     * @since  28/09/2024
     */
    actual suspend fun generate(): Key = Key(
        algorithm = algorithm,
        type = KeyType.SYMMETRIC,
        internal = crypto.subtle.generateKey(
            algorithm = when(algorithm) {
                "AES" -> AesKeyGenParams.invoke("AES-${parameters.blockMode?: Algorithm.AES.defaultBlockMode}", parameters.size.toShort())
                else -> throw IllegalArgumentException("Algorithm '$algorithm' not supported")
            },
            extractable = false,
            keyUsages = arrayOf(KeyUsage.encrypt, KeyUsage.decrypt) // TODO: Make specifiable by user
        )
    )
}
