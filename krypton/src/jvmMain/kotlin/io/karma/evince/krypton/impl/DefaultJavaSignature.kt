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

package io.karma.evince.krypton.impl

import io.karma.evince.krypton.Key
import io.karma.evince.krypton.Signature
import io.karma.evince.krypton.parameters.SignatureParameters
import java.security.PrivateKey
import java.security.PublicKey

private typealias JavaSignature = java.security.Signature

class DefaultJavaSignature(parameters: SignatureParameters) : Signature {
    private val signature: JavaSignature = JavaSignature.getInstance("${parameters.digest}with${parameters.key.algorithm.literal}")

    init {
        when (parameters.key.type) {
            Key.Type.PUBLIC -> signature.initVerify(parameters.key.javaKey as PublicKey)
            Key.Type.PRIVATE -> signature.initSign(parameters.key.javaKey as PrivateKey)
            else -> throw IllegalArgumentException()
        }
    }

    override suspend fun sign(input: ByteArray): ByteArray {
        signature.update(input)
        return signature.sign()
    }

    override suspend fun verify(signature: ByteArray, original: ByteArray): Boolean {
        this.signature.update(original)
        return this.signature.verify(signature)
    }
}
