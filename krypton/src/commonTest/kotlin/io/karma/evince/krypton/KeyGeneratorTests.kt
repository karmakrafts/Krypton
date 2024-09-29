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

import io.karma.evince.krypton.parameters.KeyGeneratorParameters
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertEquals

class KeyGeneratorTests : ShouldSpec() {
    init {
        should("test AES") {
            val usages = arrayOf(Key.Usage.ENCRYPT, Key.Usage.DECRYPT)
            val key = DefaultAlgorithm.AES.generateKey(KeyGeneratorParameters(128U, usages))
            assertEquals(key.algorithm, DefaultAlgorithm.AES)
            assertEquals(key.type, Key.Type.OTHER)
            assertEquals(key.usages, usages)
        }
    }
}
