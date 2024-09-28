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

import io.karma.evince.krypton.annotations.UncheckedKryptonAPI
import io.karma.evince.krypton.key.Key

/**
 * This class is the implementation for a cipher. A cipher is used to encrypt or decrypt data transmitted over an
 * insecure tunnel.
 * 
 * @param algorithm  The algorithm used
 * @param key        The key for the operation
 * @param parameters Extra parameters for the cipher
 *
 * @author Cedric Hammes
 * @param  20/09/2024
 */
expect class Cipher(algorithm: Algorithm, key: Key, parameters: CipherParameters) {
    /**
     * This constructor initializes the cipher with string-defined algorithm. The correctness of this string in the
     * cipher is not pre-checked by the algorithm system so you can encounter exceptions from the backends.
     *
     * @param algorithm  The unchecked algorithm name
     * @param key        The key used for the encryption/decryption
     * @param parameters The parameters like padding used for the cipher
     *
     * @author Cedric Hammes
     * @since  20/09/2024
     */
    @UncheckedKryptonAPI
    constructor(algorithm: String, key: Key, parameters: CipherParameters)
    
    /**
     * This function passes the data to the encryption/decryption backend like OpenSSL and returns the output data of
     * the cipher operation done.
     *
     * @param data The data to be processed by the cipher
     * @param aad  Additional authenticated data required for the process (by default null)
     * @returns    The processed data
     *
     * @author Cedric Hammes
     * @since  20/09/2024
     */
    fun process(data: ByteArray, aad: ByteArray? = null): ByteArray
    
    enum class Mode {
        ENCRYPT,
        DECRYPT
    }
}

/**
 * This class contains the parameters for a Cipher. It contains the configured padding mode and the configured block
 * mode. If no set, the cipher object is going to set the default padding or/and block mode.
 *
 * @param mode      The mode of the cipher
 * @param padding   The padding of the output data
 * @param blockMode The block mode of the cipher (If the cipher is a block cipher)
 * @param iv        The optional initialization vector for the cipher
 *
 * @author Cedric Hammes
 * @since  20/09/2024
 */
open class CipherParameters(
    val mode: Cipher.Mode,
    val padding: Padding? = null,
    val blockMode: BlockMode? = null,
    val iv: ByteArray? = null
) {
    internal fun validate(algorithm: Algorithm): CipherParameters = also {
        if (padding != null && algorithm.supportedPaddings.contains(padding))
            throw IllegalArgumentException(
                "Unsupported padding '$padding' for '$algorithm', please use: ${
                    algorithm.supportedPaddings.joinToString(", ")
                }"
            )
        if (blockMode != null && algorithm.supportedBlockModes.contains(blockMode))
            throw IllegalArgumentException(
                "Unsupported block mode '$blockMode' for '$algorithm', please use: ${
                    algorithm.supportedBlockModes.joinToString(
                        ", "
                    )
                }"
            )
    }
    
    override fun toString(): String = "CipherParameters(mode=$mode, padding=$padding, blockMode=$blockMode, iv=$iv)"
}

/**
 * This class is a cipher parameters class with an extra field for the length of the GCM tag. These tags are used in the
 * GCM block mode to provide integrity checks of the encrypted message.
 *
 * @param mode      The mode for the cipher (encrypt or decrypt)
 * @param padding   The padding applied after the cipher
 * @param blockMode The block mode of the cipher used
 * @param iv        The initialization vector
 * @param tagLen    The length of the tag
 *
 * @author Cedric Hammes
 * @since  20/09/2024
 */
class GCMCipherParameters(
    mode: Cipher.Mode,
    val tagLen: Int,
    padding: Padding? = null,
    blockMode: BlockMode? = null,
    iv: ByteArray? = null,
) : CipherParameters(mode, padding, blockMode, iv)

/**
 * This class is a cipher parameters class with an extra field for the counter used while encrypting and decrypting this files. These
 * counter must be the same while encryption and decryption.
 *
 * @param mode      The mode for the cipher (encrypt or decrypt)
 * @param counter   The counter used for the cipher operation
 * @param padding   The padding applied after the cipher
 * @param blockMode The block mode of the cipher used
 *
 * @author Cedric Hammes
 * @since  20/09/2024
 */
class CTRCipherParameters(
    mode: Cipher.Mode,
    counter: ByteArray,
    padding: Padding? = null,
    blockMode: BlockMode? = null,
) : CipherParameters(mode, padding, blockMode, counter)
