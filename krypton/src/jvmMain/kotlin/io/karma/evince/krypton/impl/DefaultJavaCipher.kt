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

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.Cipher
import io.karma.evince.krypton.parameters.CipherParameters
import java.security.spec.AlgorithmParameterSpec

private typealias JavaCipher = javax.crypto.Cipher

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
class DefaultJavaCipher(
    private val algorithm: Algorithm,
    private val parameters: CipherParameters,
    parameterSpecFactory: (CipherParameters) -> AlgorithmParameterSpec?
) : Cipher {
    private val cipher: JavaCipher = JavaCipher.getInstance(toString())

    init {
        when (val parameterSpec = parameterSpecFactory(parameters)) {
            null -> cipher.init(
                if (parameters.mode == Cipher.Mode.ENCRYPT) JavaCipher.ENCRYPT_MODE else JavaCipher.DECRYPT_MODE,
                parameters.key.javaKey
            )

            else -> cipher.init(
                if (parameters.mode == Cipher.Mode.ENCRYPT) JavaCipher.ENCRYPT_MODE else JavaCipher.DECRYPT_MODE,
                parameters.key.javaKey,
                parameterSpec
            )
        }
    }

    override suspend fun run(input: ByteArray, aad: ByteArray?): ByteArray {
        cipher.update(input)
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal()
    }

    override fun toString(): String =
        "${algorithm.literal}/${parameters.blockMode ?: algorithm.defaultBlockMode}/${parameters.padding ?: algorithm.defaultPadding}"
}
