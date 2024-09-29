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
import io.karma.evince.krypton.Key

/**
 * This class implements the default KeyGenerator parameters. These parameters are specified to tell the key generator more about the key
 * you want to generate.
 *
 * @param bitSize The size in bits of the key
 * @param usages  The key's usages
 *
 * @author Cedric Hammes
 * @since  29/09/2024
 */
open class KeyGeneratorParameters(val bitSize: UShort, val usages: Array<Key.Usage>, val blockMode: Algorithm.BlockMode? = null)
