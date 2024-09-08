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

package io.karma.evince.krypton.hashes

import java.security.MessageDigest

actual class Digest actual constructor(string: String, size: Int) : AutoCloseable {
    private val digest = MessageDigest.getInstance(string)

    actual constructor(type: DigestType, size: Int) : this(type.toString(), size)

    actual fun hash(value: ByteArray): ByteArray = digest.digest(value)
    actual override fun close() {}
}
