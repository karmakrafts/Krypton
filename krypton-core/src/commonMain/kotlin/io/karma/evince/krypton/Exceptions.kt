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
 * This exception is thrown if an operation with the Krypton API fails.
 *
 * @author Cedric Hammes
 * @since  26/09/2024
 */
open class KryptonException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * This exception is thrown when the initialization of a cryptographic API like the key generation API or the cipher
 * API fails.
 *
 * @author Cedric Hammes
 * @since  26/09/2024
 */
class InitializationException(message: String, cause: Throwable? = null) : KryptonException(message, cause)

/**
 * This exception is thrown when the generation of keys or parameters fails.
 *
 * @author Cedric Hammes
 * @since  26/09/2024
 */
class GenerationException(message: String, cause: Throwable? = null) : KryptonException(message, cause)

/**
 * This exception is thrown if a cipher operation (encrypt data or decrypt data) fails.
 *
 * @author Cedric Hammes
 * @since 27/09/2024
 */
class CipherOperationException(message: String, cause: Throwable? = null) : KryptonException(message, cause)
