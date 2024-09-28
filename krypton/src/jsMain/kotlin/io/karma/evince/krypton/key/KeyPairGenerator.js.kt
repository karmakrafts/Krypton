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
import io.karma.evince.krypton.Padding
import io.karma.evince.krypton.annotations.UncheckedKryptonAPI
import js.typedarrays.Uint8Array
import web.crypto.CryptoKeyPair
import web.crypto.EcKeyGenParams
import web.crypto.KeyAlgorithm
import web.crypto.KeyUsage
import web.crypto.RsaHashedKeyGenParams
import web.crypto.crypto

/**
 * @author Cedric Hammes
 * @since  28/09/2024
 *
 * @see [RSA-PSS, Web Cryptography API Examples](https://github.com/diafygi/webcrypto-examples?tab=readme-ov-file#rsa-pss---generatekey)
 * @see [ECDH, Web Cryptography API Examples](https://github.com/diafygi/webcrypto-examples?tab=readme-ov-file#ecdh---generatekey)
 * @see [Web Cryptography API, W3C](https://w3c.github.io/webcrypto/#crypto-interface)
 */
actual class KeyPairGenerator @UncheckedKryptonAPI actual constructor(
    private val algorithm: String,
    private val parameters: KeyPairGeneratorParameters
) {
    actual constructor(algorithm: Algorithm, parameters: KeyPairGeneratorParameters) :
            this(algorithm.validOrError(Algorithm.Scope.KEYPAIR_GENERATOR).toString(), parameters)

    /**
     * This function generates a private key and derives the public key from the private key. These operations are done
     * in the backend and the backend-internal structure is wrapped into a key.
     *
     * @author Cedric Hammes
     * @since  28/09/2024
     */
    actual suspend fun generate(): KeyPair = (crypto.subtle.generateKey(
        algorithm = when (algorithm) {
            "RSA" -> when (val padding = parameters.padding?: Algorithm.RSA.defaultPadding) {
                Padding.OAEP_SHA1, Padding.OAEP_SHA256 -> RsaHashedKeyGenParams.invoke(
                    name = "RSA-OAEP",
                    modulusLength = parameters.size,
                    publicExponent = Uint8Array(arrayOf(1, 0, 1)),
                    hash = KeyAlgorithm.invoke(requireNotNull(padding.digest))
                ) // TODO: Add support for PKCS1 and no padding
                else -> throw IllegalArgumentException("Unsupported padding $padding")
            }
            "ECDH" -> {
                if (parameters !is ECKeyPairGeneratorParameters)
                    throw IllegalArgumentException("Illegal parameters type '${parameters::class.js.name}'")
                EcKeyGenParams.invoke("ECDH", parameters.curve.toString())
            } // TODO: Add support for DH
            else -> throw IllegalArgumentException("Algorithm '$algorithm' not supported")
        },
        extractable = false,
        keyUsages = parameters.usages.toWebCrypto()
    ).unsafeCast<CryptoKeyPair>()).let {
        KeyPair(
            Key(algorithm, Key.Type.PUBLIC, parameters.usages.forType(Key.Type.PUBLIC), it.publicKey),
            Key(algorithm, Key.Type.PRIVATE, parameters.usages.forType(Key.Type.PRIVATE), it.publicKey)
        )
    }
}
