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
 * This class is the key generator. A key generator is a class designed to generate keys based on the users parameters
 * specified. These parameters can be entered by the user itself or generated by a generator which are
 * provided by this API.
 *
 * @author Cedric Hamems
 * @since  08/09/2024
 */
expect class KeyGenerator @UncheckedKryptonAPI constructor(algorithm: String, parameter: KeyGeneratorParameter) {
    constructor(algorithm: Algorithm, parameter: KeyGeneratorParameter)
    
    fun generate(): Key
}

/**
 * This class defines the required parameters for using a key generator. These parameters are the base of all algorithm
 * parameters this API provides.
 *
 * @author Cedric Hammes
 * @since  08/09/2024
 */
open class KeyGeneratorParameter(internal val size: Int)
