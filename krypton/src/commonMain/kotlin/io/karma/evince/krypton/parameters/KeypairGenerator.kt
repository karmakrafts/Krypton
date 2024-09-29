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

import com.ionspin.kotlin.bignum.integer.BigInteger
import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.EllipticCurve
import io.karma.evince.krypton.Key

/**
 * This class implements the default KeypairGenerator parameters. These parameters are specified to tell the keypair generator more about
 * the key you want to generate.
 *
 * @param bitSize   The size in bits of the key
 * @param usages    The key's usages
 * @param blockMode The algorithm's block mode
 * @param padding   The padding used
 *
 * @author Cedric Hammes
 * @since  09/09/2024
 */
open class KeypairGeneratorParameters(
    val bitSize: UShort,
    val usages: Array<Key.Usage>,
    val blockMode: Algorithm.BlockMode? = null,
    val padding: Algorithm.Padding? = null
): Parameters

/**
 * This class defines the required parameters for the generation of keys for elliptic curve based algorithms like the
 * ECDH algorithm. These parameters are defined by the user.
 *
 * @author Cedric Hammes
 * @since  09/09/2024
 */
class ECKeypairGeneratorParameters(
    val curve: EllipticCurve,
    usages: Array<Key.Usage>
) : KeypairGeneratorParameters(0U, usages)

/**
 * This class defines the optional parameters for the generation of keys for the Diffie-Hellman key exchange
 * algorithm. These parameters should be created with a parameter generator or derived from traffic with
 * another party.
 *
 * @author Cedric Hammes
 * @since  17/09/2024
 */
class DHKeypairGeneratorParameters(
    val p: BigInteger,
    val g: BigInteger,
    bits: UShort,
    usages: Array<Key.Usage>
) : KeypairGeneratorParameters(bits, usages)
