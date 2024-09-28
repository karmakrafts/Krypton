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
import js.typedarrays.Uint8Array
import js.typedarrays.toUint8Array
import web.crypto.crypto

/**
 * @author Cedric Hammes
 * @since  28/09/2024
 * @suppress
 */
actual class Digest @UncheckedKryptonAPI actual constructor(private val algorithm: String, size: Int) : AutoCloseable {
    actual constructor(algorithm: Algorithm, size: Int) : this(algorithm.validOrError(Algorithm.Scope.DIGEST).toString(), size)

    actual suspend fun hash(value: ByteArray): ByteArray = Uint8Array(crypto.subtle.digest(algorithm, value.toUint8Array())).toByteArray()

    actual override fun close() {
    }

}
