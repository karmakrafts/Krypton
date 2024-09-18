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

package io.karma.evince.krypton.key

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.utils.JavaCryptoHelper

private typealias JavaKeyAgreement = javax.crypto.KeyAgreement

actual class KeyAgreement actual constructor(algorithm: String, privateKey: Key) : AutoCloseable {
    private val keyAgreement: JavaKeyAgreement

    actual constructor(algorithm: Algorithm, privateKey: Key) :
            this(algorithm.checkScopeOrError(Algorithm.Scope.KEY_AGREEMENT).toString(), privateKey)

    init {
        JavaCryptoHelper.installBouncyCastleProviders()
        this.keyAgreement = JavaKeyAgreement.getInstance(algorithm)
        this.keyAgreement.init(privateKey.internalValue)
    }

    actual fun generateSecret(peerPublicKey: Key): ByteArray {
        this.keyAgreement.doPhase(peerPublicKey.internalValue, true) // TODO: Add compatibility for doPhase = false
        return this.keyAgreement.generateSecret()
    }

    override fun close() {}
}
