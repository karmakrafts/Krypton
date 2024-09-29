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

import io.karma.evince.krypton.parameters.CipherParameters
import io.karma.evince.krypton.parameters.KeyGeneratorParameters
import io.karma.evince.krypton.parameters.KeypairGeneratorParameters
import io.karma.evince.krypton.parameters.ParameterGeneratorParameters
import io.karma.evince.krypton.parameters.Parameters
import io.karma.evince.krypton.parameters.SignatureParameters

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
    fun hash(input: ByteArray): ByteArray
}

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
interface CipherFactory : CryptoProvider {
    /**
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    fun createCipher(parameters: CipherParameters): Cipher
}

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
interface SignatureFactory : CryptoProvider {
    /**
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    fun createSignature(parameters: SignatureParameters): Signature
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
    fun computeSecret(privateKey: Key, peerPublicKey: Key): ByteArray
}

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
interface KeyGenerator : CryptoProvider {
    /**
     * @param parameters The parameters for the key generation procedure
     * @return           The generated key for the algorithm
     *
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    fun generateKey(parameters: KeyGeneratorParameters): Key
}

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
interface KeypairGenerator : CryptoProvider {
    /**
     * @param parameters The parameters for the keypair generation procedure
     * @return           The generated keypair for the algorithm
     *
     * @author Cedric Hammes
     * @since  29/09/2024
     */
    fun generateKeypair(parameters: KeypairGeneratorParameters): Keypair
}

/**
 * @author Cedric Hammes
 * @since  30/09/2024
 */
interface ParameterGenerator : CryptoProvider {
    /**
     * @author Cedric Hammes
     * @since  30/09/2024
     */
    fun <T: Parameters> generateParameters(parameters: ParameterGeneratorParameters): T
}
