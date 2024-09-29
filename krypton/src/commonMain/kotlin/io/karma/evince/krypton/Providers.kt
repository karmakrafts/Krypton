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

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
interface CryptoProvider

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
interface Hash : CryptoProvider {
    /**
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    suspend fun hash(input: ByteArray): ByteArray
}

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
interface Cipher : CryptoProvider { // TODO: Add parameters and key
    /**
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    suspend fun encrypt(key: Any, input: ByteArray, aad: ByteArray?): ByteArray

    /**
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    suspend fun decrypt(key: Any, input: ByteArray, aad: ByteArray?): ByteArray
}

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
interface Signature : CryptoProvider { // TODO: Add parameters and key
    /**
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    suspend fun sign(privateKey: Key, input: ByteArray): ByteArray

    /**
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    suspend fun verify(publicKey: Key, signature: ByteArray, original: ByteArray): Boolean
}

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
interface KeyAgreement : CryptoProvider {
    /**
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    suspend fun computeSecret(privateKey: Key, peerPublicKey: Any): ByteArray
}

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
interface KeyGenerator : CryptoProvider { // TODO: Add parameters
    /**
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    suspend fun generateKey(): Key
}

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
interface KeypairGenerator : CryptoProvider { // TODO: Add parameters
    /**
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    suspend fun generateKeypair(): KeyPair
}
