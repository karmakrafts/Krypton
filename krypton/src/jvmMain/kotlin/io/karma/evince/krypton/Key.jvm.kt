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

import java.security.PrivateKey
import java.security.PublicKey

private typealias JavaKey = java.security.Key

/** @suppress **/
@Suppress("MemberVisibilityCanBePrivate")
actual class Key(val javaKey: JavaKey, actual val algorithm: Algorithm, actual val usages: Array<Usage>) : AutoCloseable {
    actual val type: Type = when (javaKey) {
        is PrivateKey -> Type.PRIVATE
        is PublicKey -> Type.PUBLIC
        else -> Type.OTHER
    }

    init {
        if (javaKey.algorithm != algorithm.literal) {
            throw IllegalArgumentException(
                "The internal key's algorithm '${javaKey.algorithm}' is not matching with the key algorithm ${algorithm.literal}"
            )
        }
    }

    actual override fun close() {} // Not needed on JVM

    actual enum class Usage {
        ENCRYPT, DECRYPT, DERIVE, SIGN, VERIFY
    }

    actual enum class Type(private val literal: String) {
        PUBLIC("public"), PRIVATE("private"), OTHER("symmetric");
        override fun toString(): String = literal
    }

}
