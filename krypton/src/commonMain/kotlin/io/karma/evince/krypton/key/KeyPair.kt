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

/**
 * This class holds a private-public key pair. These key pairs are used while operating with asymmetric algorithms like
 * RSA or key agreements like Diffie-Hellman.
 *
 * @param privateKey The private key of the keypair
 * @param publicKey  The public key of the keypair
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
data class KeyPair(val publicKey: Key, val privateKey: Key) : AutoCloseable {
    override fun close() {
        publicKey.close()
        privateKey.close()
    }
}
