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

import com.ionspin.kotlin.bignum.integer.BigInteger
import io.karma.evince.krypton.Algorithm
import io.karma.evince.krypton.annotations.UncheckedKryptonAPI
import io.karma.evince.krypton.ec.EllipticCurve

/**
 * This class is the keypair generator. A keypair generator is a class designed to generate key pairs based on the users
 * parameters specified. These parameters can be entered by the user itself or generated by a generator which are
 * provided by this API.
 *
 * @author Cedric Hamems
 * @since  09/09/2024
 */
expect class KeyPairGenerator @UncheckedKryptonAPI constructor(
    algorithm: String,
    parameters: KeyPairGeneratorParameters
) {
    constructor(algorithm: Algorithm, parameters: KeyPairGeneratorParameters)
    
    /**
     * This function generates a private key and derives the public key from the private key. These operations are done
     * in the backend and the backend-internal structure is wrapped into a key.
     *
     * @author Cedric Hammes
     * @since  26/09/2024
     */
    fun generate(): KeyPair
}

/**
 * This class defines the required parameters for using a keypair generator. These parameters are the base of all
 * algorithm parameters this API provides.
 *
 * @author Cedric Hammes
 * @since  09/09/2024
 */
open class KeyPairGeneratorParameters(internal val size: Int)

/**
 * This class defines the required parameters for the generation of keys for elliptic curve based algorithms like the
 * ECDH algorithm. These parameters are defined by the user.
 *
 * @author Cedric Hammes
 * @since  09/09/2024
 */
class ECKeyPairGeneratorParameters(internal val curve: EllipticCurve) : KeyPairGeneratorParameters(0)

/**
 * This class defines the optional parameters for the generation of keys for the Diffie-Hellman key exchange
 * algorithm. These parameters should be created with a parameter generator or derived from traffic with
 * another party.
 *
 * @author Cedric Hammes
 * @since  17/09/2024
 */
class DHKeyPairGeneratorParameters(internal val p: BigInteger, internal val g: BigInteger, bits: Int)
    : KeyPairGeneratorParameters(bits)
