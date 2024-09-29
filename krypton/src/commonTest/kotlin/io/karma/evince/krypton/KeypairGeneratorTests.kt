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

import io.karma.evince.krypton.parameters.KeypairGeneratorParameters
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KeypairGeneratorTests : ShouldSpec() {
    init {
        should("test RSA") {
            val usages = arrayOf(Key.Usage.ENCRYPT, Key.Usage.DECRYPT)
            DefaultAlgorithm.RSA.generateKeypair(KeypairGeneratorParameters(2048U, usages)).use { keypair ->
                assertEquals(DefaultAlgorithm.RSA, keypair.public.algorithm)
                assertEquals(Key.Type.PUBLIC, keypair.public.type)
                assertTrue { usages.contentEquals(keypair.public.usages) }
                assertEquals(DefaultAlgorithm.RSA, keypair.private.algorithm)
                assertEquals(Key.Type.PRIVATE, keypair.private.type)
                assertTrue { usages.contentEquals(keypair.private.usages) }
            }
        }
    }
}
