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

package de.karma.evince.krypton.hashes

import io.karma.evince.krypton.Digest
import io.karma.evince.krypton.DigestType
import io.karma.evince.krypton.hashToString
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertEquals

class DigestTests : ShouldSpec() {
    init {
        should("test SHA3") {
            Digest(DigestType.SHA3_224).use { digest ->
                assertEquals(
                    "d40cc4f9630f21eef0b185bdd6a51eab1775c1cd6ae458066ecaf046",
                    digest.hashToString("Test")
                )
            }
            Digest(DigestType.SHA3_256).use { digest ->
                assertEquals(
                    "c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0",
                    digest.hashToString("Test")
                )
            }
            Digest(DigestType.SHA3_384).use { digest ->
                assertEquals(
                    "da73bfcba560692a019f52c37de4d5e3ab49ca39c6a75594e3c39d805388c4de9d0ff3927eb9e197536f5b0b3a515f0a",
                    digest.hashToString("Test")
                )
            }
            Digest(DigestType.SHA3_512).use { digest ->
                assertEquals(
                    "301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7",
                    digest.hashToString("Test")
                )
            }
        }

        should("test SHA") {
            Digest(DigestType.SHA224).use { digest ->
                assertEquals(
                    "3606346815fd4d491a92649905a40da025d8cf15f095136b19f37923",
                    digest.hashToString("Test")
                )
            }
            Digest(DigestType.SHA256).use { digest ->
                assertEquals(
                    "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
                    digest.hashToString("Test")
                )
            }
            Digest(DigestType.SHA384).use { digest ->
                assertEquals(
                    "7b8f4654076b80eb963911f19cfad1aaf4285ed48e826f6cde1b01a79aa73fadb5446e667fc4f90417782c91270540f3",
                    digest.hashToString("Test")
                )
            }
            Digest(DigestType.SHA512).use { digest ->
                assertEquals(
                    "c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31",
                    digest.hashToString("Test")
                )
            }
        }

        should("test MD5") {
            Digest(DigestType.MD5).use { digest ->
                assertEquals(
                    "0cbc6611f5540bd0809a388dc95a615b",
                    digest.hashToString("Test")
                )
            }
        }
    }
}