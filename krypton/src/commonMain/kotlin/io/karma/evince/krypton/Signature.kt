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

import io.karma.evince.krypton.annotations.UncheckedKryptonAPI
import io.karma.evince.krypton.key.Key

/**
 * This class is the implementation for signatures. It can be used to sign arbitrary data and verify them with the
 * original data.
 *
 * @param key        The key used for verification and signing
 * @param algorithm  The algorithm used for signing
 * @param parameters Extra parameters for the signature
 *
 * @author Cedric Hammes
 * @since  27/09/2024
 */
expect class Signature(key: Key, algorithm: Algorithm, parameters: SignatureParameters) {
    @UncheckedKryptonAPI constructor(key: Key, algorithm: String, parameters: SignatureParameters)
    
    fun sign(data: ByteArray): ByteArray
    fun verify(signature: ByteArray, data: ByteArray): Boolean
}

/**
 * This class contains the digest used in combination with the signature algorithm while signing and verifying the
 * data.
 *
 * @author Cedric Hammes
 * @since  27/09/2024
 */
data class SignatureParameters(val digest: String, val type: EnumType) {
    constructor(digest: Algorithm, type: EnumType) :
            this(digest.validOrError(Algorithm.Scope.DIGEST).toString(), type)
    
    enum class EnumType(internal val keyType: Key.Type) {
        VERIFY(Key.Type.PUBLIC),
        SIGN(Key.Type.PRIVATE)
    }
}
