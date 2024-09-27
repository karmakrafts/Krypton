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
import java.security.PrivateKey
import java.security.PublicKey

private typealias JavaSignature = java.security.Signature

/**
 * @author Cedric Hammes
 * @since  27/09/2024
 * @suppress
 */
actual class Signature actual constructor(key: Key, algorithm: String, private val parameters: SignatureParameters) {
    private val internal: JavaSignature = JavaSignature.getInstance("${parameters.digest}with${algorithm}")
    
    actual constructor(key: Key, algorithm: Algorithm, parameters: SignatureParameters) :
            this(key, algorithm.checkScopeOrError(Algorithm.Scope.SIGNATURE).toString(), parameters)
    
    init {
        if (parameters.type == SignatureParameters.EnumType.VERIFY)
            internal.initVerify(key.internalValue as PublicKey)
        else
            internal.initSign(key.internalValue as PrivateKey)
    }
    
    actual fun sign(data: ByteArray): ByteArray {
        if (parameters.type != SignatureParameters.EnumType.SIGN)
            throw KryptonException("You can't sign data with this signature instance")
        
        internal.update(data)
        return internal.sign()
    }
    
    actual fun verify(signature: ByteArray, data: ByteArray): Boolean {
        if (parameters.type != SignatureParameters.EnumType.VERIFY)
            throw KryptonException("You can't verify signatures with this signature instance")
        
        internal.update(data)
        return internal.verify(signature)
    }
}
