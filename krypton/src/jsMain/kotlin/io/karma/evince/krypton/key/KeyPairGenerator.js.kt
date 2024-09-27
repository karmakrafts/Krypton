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
 * @author Cedric Hammes
 * @since  28/09/2024
 * @suppress
 */
actual class KeyPairGenerator @UncheckedKryptonAPI actual constructor(
    algorithm: String,
    parameters: KeyPairGeneratorParameters
) {
    actual constructor(algorithm: Algorithm, parameters: KeyPairGeneratorParameters) :
            this(algorithm.validOrError(Algorithm.Scope.KEYPAIR_GENERATOR).toString(), parameters)

    /**
     * This function generates a private key and derives the public key from the private key. These operations are done
     * in the backend and the backend-internal structure is wrapped into a key.
     *
     * @author Cedric Hammes
     * @since  26/09/2024
     */
    actual fun generate(): KeyPair {
        TODO("Not yet implemented")
    }

}
