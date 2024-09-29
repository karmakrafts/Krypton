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

import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertEquals

class MessageDigestTests : ShouldSpec() {
    init {
        should("test SHA-1") {
            assertEquals(
                expected = "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa",
                actual = DefaultAlgorithm.SHA1.hashToString("Test"),
                message = "SHA-1 hashing failed"
            )
        }

        should("test SHA-2 family") {
            assertEquals(
                expected = "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
                actual = DefaultAlgorithm.SHA256.hashToString("Test"),
                message = "SHA-256 (SHA-2 family) hashing failed"
            )
            assertEquals(
                expected = "7b8f4654076b80eb963911f19cfad1aaf4285ed48e826f6cde1b01a79aa73fadb5446e667fc4f90417782c91270540f3",
                actual = DefaultAlgorithm.SHA384.hashToString("Test"),
                message = "SHA-384 (SHA-2 family) hashing failed"
            )
            assertEquals(
                expected = "c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31",
                actual = DefaultAlgorithm.SHA512.hashToString("Test"),
                message = "SHA-512 (SHA-2 family) hashing failed"
            )
        }
    }
}
