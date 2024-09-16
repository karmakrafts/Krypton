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
import io.karma.evince.krypton.annotations.UncheckedKryptonAPI

/**
 * This class represents the key agreement class for Krypton. This class allows to derive a secret from key agreements
 * by using algorithms like ECDH (Elliptic Curve Diffie-Hellman) or DH (Diffie-Hellman) key exchange. You have to
 * specify your private key in the constructor.
 *
 * @author Cedric Hammes
 * @since  17/09/2024
 */
expect class KeyAgreement @UncheckedKryptonAPI constructor(algorithm: String, privateKey: Key) {
    constructor(algorithm: Algorithm, privateKey: Key)

    /**
     * This function derives the secret from the peer's public key combined with the private key specified in the
     * constructor. This secret should not be used directly for cryptographic algorithms
     *
     * @author Cedric Hammes
     * @since  17/09/2024
     */
    fun generateSecret(peerPublicKey: Key): ByteArray
}
