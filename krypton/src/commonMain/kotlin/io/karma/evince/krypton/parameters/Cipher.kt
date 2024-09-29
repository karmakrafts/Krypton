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

package io.karma.evince.krypton.parameters

import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.Cipher
import io.karma.evince.krypton.Key

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
open class CipherParameters(
    val blockMode: Algorithm.BlockMode?,
    val padding: Algorithm.Padding?,
    val mode: Cipher.Mode,
    val key: Key
)

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
open class CBCCipherParameters(
    mode: Cipher.Mode,
    key: Key,
    val iv: ByteArray,
    blockMode: Algorithm.BlockMode? = null,
    padding: Algorithm.Padding? = null
): CipherParameters(blockMode, padding, mode, key)

/**
 * @author Cedric Hammes
 * @since  29/09/2024
 */
class GCMCipherParameters(
    mode: Cipher.Mode,
    key: Key,
    iv: ByteArray,
    val tagLength: Int,
    blockMode: Algorithm.BlockMode? = null,
    padding: Algorithm.Padding? = null
) : CBCCipherParameters(mode, key, iv, blockMode, padding)
