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

/**
 * @author Cedric Hammes
 * @since  28/09/2024
 * @suppress
 */
actual class KeyAgreement @UncheckedKryptonAPI actual constructor(algorithm: String, privateKey: Key) : AutoCloseable {
    actual constructor(algorithm: Algorithm, privateKey: Key) :
            this(algorithm.validOrError(Algorithm.Scope.KEY_AGREEMENT).toString(), privateKey)

    actual fun generateSecret(peerPublicKey: Key): ByteArray {
        TODO("Not yet implemented")
    }

    actual override fun close() {
    }

}
