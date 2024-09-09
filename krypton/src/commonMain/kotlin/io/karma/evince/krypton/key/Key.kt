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

/**
 * This class is a cross-platform implementation for a key (with support for symmetric and asymmetric keys) that can be
 * used in all parts of the Krypton API like Key generation and signing.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
expect class Key : AutoCloseable {
    val algorithm: String
    val type: KeyType
    override fun close()
}

/**
 * This enum represents all types available for keys. Symmetric if the key is symmetric and public or private if the key
 * is from an asymmetric algorithm.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
enum class KeyType {
    SYMMETRIC,
    PUBLIC,
    PRIVATE
}
