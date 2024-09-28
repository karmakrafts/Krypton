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

import io.karma.evince.krypton.key.Key
import io.karma.evince.krypton.utils.JavaCryptoHelper
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

private typealias JavaCipher = javax.crypto.Cipher

private fun CipherParameters.toAlgorithmSpecification(algorithm: String): String =
    "$algorithm${blockMode?.let { "/$it" }?: ""}${padding?.let { "/$it" }?: ""}"

private val Cipher.Mode.javaCipherMode: Int
    get() = if (this == Cipher.Mode.ENCRYPT) JavaCipher.ENCRYPT_MODE else JavaCipher.DECRYPT_MODE

/** @suppress **/
actual class Cipher actual constructor(algorithm: String, key: Key, parameters: CipherParameters) {
    private val internal: JavaCipher = JavaCipher.getInstance(parameters.toAlgorithmSpecification(algorithm))
    
    actual constructor(algorithm: Algorithm, key: Key, parameters: CipherParameters) :
            this(algorithm.validOrError(Algorithm.Scope.CIPHER).toString(), key, parameters.validate(algorithm))
    
    init {
        JavaCryptoHelper.installBouncyCastleProviders()
        val parameterSpec = when {
            parameters is GCMCipherParameters -> GCMParameterSpec(parameters.tagLen, parameters.iv)
            parameters.iv != null -> IvParameterSpec(parameters.iv)
            else -> null
        }
        
        if (parameterSpec != null) {
            internal.init(parameters.mode.javaCipherMode, key.internalValue, parameterSpec)
        } else {
            internal.init(parameters.mode.javaCipherMode, key.internalValue)
        }
    }
    
    actual suspend fun process(data: ByteArray, aad: ByteArray?): ByteArray {
        aad?.let { internal.updateAAD(it) }
        return internal.doFinal(data)
    }
    
    actual enum class Mode {
        ENCRYPT, DECRYPT
    }
}
