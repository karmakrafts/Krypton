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

data class KeyPair(val private: Key, val public: Key) : AutoCloseable {
    override fun close() {
        private.close()
        public.close()
    }
}

expect class Key : AutoCloseable {
    val algorithm: Algorithm
    val usages: Array<Usage>
    val type: Type
    override fun close()

    enum class Usage {
        ENCRYPT,
        DECRYPT,
        DERIVE,
        SIGN,
        VERIFY
    }

    enum class Type {
        PUBLIC,
        PRIVATE,
        OTHER
    }
}
