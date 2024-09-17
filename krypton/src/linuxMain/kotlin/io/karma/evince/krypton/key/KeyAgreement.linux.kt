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
import io.karma.evince.krypton.utils.ErrorHelper
import kotlinx.cinterop.*
import libssl.*

actual class KeyAgreement actual constructor(algorithm: String, privateKey: Key) : AutoCloseable {
    private val derivationContext: CPointer<EVP_PKEY_CTX>

    actual constructor(algorithm: Algorithm, privateKey: Key) :
            this(algorithm.checkScopeOrError(Algorithm.Scope.KEY_AGREEMENT).toString(), privateKey)

    init {
        if (privateKey.body !is Key.KeyBody.EVPKeyBody || privateKey.type != KeyType.PRIVATE)
            throw RuntimeException("The specified private key isn't a private key")

        derivationContext = requireNotNull(EVP_PKEY_CTX_new(privateKey.body.key, null))
        if (EVP_PKEY_derive_init(derivationContext) != 1)
            throw RuntimeException("Unable to initialize Key Agreement", ErrorHelper.createOpenSSLException())
    }

    actual fun generateSecret(peerPublicKey: Key): ByteArray {
        if (peerPublicKey.body !is Key.KeyBody.EVPKeyBody || peerPublicKey.type != KeyType.PUBLIC)
            throw RuntimeException("The specified public key isn't a private key")

        if (EVP_PKEY_derive_set_peer(derivationContext, peerPublicKey.body.key) != 1)
            throw RuntimeException("Unable to set public key for agreement", ErrorHelper.createOpenSSLException())

        memScoped {
            val secretLength = alloc<ULongVar>()
            if (EVP_PKEY_derive(derivationContext, null, secretLength.ptr) != 1)
                throw RuntimeException("Unable to acquire length of secret")

            val secret = UByteArray(secretLength.value.toInt())
            secret.usePinned { pinnedSecret ->
                if (EVP_PKEY_derive(derivationContext, pinnedSecret.addressOf(0), secretLength.ptr) != 1)
                    throw RuntimeException("Unable to acquire length of secret")
            }
            return secret.toByteArray()
        }
    }

    override fun close() {
        EVP_PKEY_CTX_free(derivationContext)
    }
}
