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

package io.karma.evince.krypton.nonjs

import io.karma.evince.krypton.DefaultAlgorithm
import io.kotest.core.spec.style.ShouldSpec
import kotlin.test.assertEquals

class MessageDigestTests : ShouldSpec() {
    init {
        should("test MD5") {
            assertEquals(
                expected = "0cbc6611f5540bd0809a388dc95a615b",
                actual = DefaultAlgorithm.MD5.hashToString("Test"),
                message = "MD5 hashing failed"
            )
        }

        should("test SHA-2 family") {
            assertEquals(
                expected = "7b8f4654076b80eb963911f19cfad1aaf4285ed48e826f6cde1b01a79aa73fadb5446e667fc4f90417782c91270540f3",
                actual = DefaultAlgorithm.SHA384.hashToString("Test"),
                message = "SHA-384 (SHA-2 family) hashing failed"
            )
        }
        should("test SHA-3 family") {
            assertEquals(
                expected = "d40cc4f9630f21eef0b185bdd6a51eab1775c1cd6ae458066ecaf046",
                actual = DefaultAlgorithm.SHA3_224.hashToString("Test"),
                message = "SHA3-224 hashing failed"
            )
            assertEquals(
                expected = "c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0",
                actual = DefaultAlgorithm.SHA3_256.hashToString("Test"),
                message = "SHA3-256 hashing failed"
            )
            assertEquals(
                expected = "da73bfcba560692a019f52c37de4d5e3ab49ca39c6a75594e3c39d805388c4de9d0ff3927eb9e197536f5b0b3a515f0a",
                actual = DefaultAlgorithm.SHA3_384.hashToString("Test"),
                message = "SHA3-384 hashing failed"
            )
            assertEquals(
                expected = "301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7",
                actual = DefaultAlgorithm.SHA3_512.hashToString("Test"),
                message = "SHA3-384 hashing failed"
            )
        }
    }
}