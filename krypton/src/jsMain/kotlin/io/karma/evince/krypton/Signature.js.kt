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
 * @author Cedric Hammes
 * @since  29/09/2024
 * @suppress
 */
actual class Signature actual constructor(
    key: Key,
    algorithm: String,
    parameters: SignatureParameters
) {
    @UncheckedKryptonAPI actual constructor(key: Key, algorithm: Algorithm, parameters: SignatureParameters) :
            this(key, algorithm.validOrError(Algorithm.Scope.SIGNATURE).toString(), parameters)

    actual fun sign(data: ByteArray): ByteArray {
        TODO("Not yet implemented")
    }

    actual fun verify(signature: ByteArray, data: ByteArray): Boolean {
        TODO("Not yet implemented")
    }

}
