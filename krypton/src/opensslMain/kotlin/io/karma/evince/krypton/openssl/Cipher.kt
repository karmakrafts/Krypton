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

package io.karma.evince.krypton.openssl

import io.karma.evince.krypton.Cipher
import io.karma.evince.krypton.CipherException
import io.karma.evince.krypton.InitializationException
import io.karma.evince.krypton.Key
import io.karma.evince.krypton.OpenSSLException
import io.karma.evince.krypton.annotations.InternalKryptonAPI
import io.karma.evince.krypton.internal.openssl.*
import io.karma.evince.krypton.parameters.CBCCipherParameters
import io.karma.evince.krypton.parameters.CipherParameters
import io.karma.evince.krypton.utils.checkNotNull
import io.karma.evince.krypton.utils.withFree
import kotlinx.cinterop.*
import platform.posix.size_t


/**
 * This function creates an internal cipher closure by the specified values. The internal cipher is completely based on
 * OpenSSL. This function can be used by other developers to increase the functionality of the API for their own needs.
 *
 * @param configurator The configurator for the context after the initialization
 * @returns            The aOTHER encryption/decryption cipher closure
 *
 * @author Cedric Hammes
 * @since  27/09/2024
 */
@InternalKryptonAPI
fun asymmetricCipher(
    configurator: (CPointer<EVP_PKEY_CTX>, CipherParameters) -> Unit
): (CipherParameters, ByteArray, ByteArray?) -> ByteArray = { parameters, data, _ ->
    val key = parameters.key
    if (key.type == Key.Type.OTHER || key.body !is Key.KeyBody.EVPKeyBody) {
        throw InitializationException("The key type '${key.type}' is not supported")
    }

    val context = EVP_PKEY_CTX_new(key.body.key, null).checkNotNull()
    withFree {
        when (parameters.mode) {
            Cipher.Mode.ENCRYPT -> {
                if (EVP_PKEY_encrypt_init(context) != 1) {
                    throw InitializationException("Unable to initialize cipher", OpenSSLException.create())
                }

                configurator(context, parameters)
                doCipherOperation(context, data, ::EVP_PKEY_encrypt)
            }

            Cipher.Mode.DECRYPT -> {
                if (EVP_PKEY_decrypt_init(context) != 1) {
                    throw InitializationException("Unable to initialize cipher", OpenSSLException.create())
                }

                configurator(context, parameters)
                doCipherOperation(context, data, ::EVP_PKEY_decrypt)
            }
        }
    }
}

/**
 * This function is a wrapper around the cryptographic encryption or decryption operation done with a cipher. This
 * function is existent to reduce code duplication in the internal cipher. This API is internal because the developer
 * don't need it in any case.
 *
 * @param context   The OpenSSL cipher context
 * @param dataInput The input data to be encrypted
 * @param closure   The OpenSSL encryption/decryption closure
 * @return          The encrypted byte array (with padding if set)
 *
 * @author Cedric Hammes
 * @since  27/09/2024
 */
@InternalKryptonAPI
fun doCipherOperation(
    context: CPointer<EVP_PKEY_CTX>,
    dataInput: ByteArray,
    closure: (CPointer<EVP_PKEY_CTX>, CPointer<UByteVar>?, CPointer<ULongVar>, CPointer<UByteVar>, ULong) -> Int
): ByteArray = memScoped {
    val outputSize = alloc<size_t>(0U)
    dataInput.usePinned { input ->
        // Determine length
        if (closure(context, null, outputSize.ptr, input.addressOf(0).reinterpret(), dataInput.size.toULong()) != 1) {
            throw RuntimeException(
                message = "Unable to get output length",
                cause = OpenSSLException.create()
            )
        }

        // Do it
        val output = ByteArray(outputSize.value.toInt())
        output.usePinned { out ->
            if (closure(
                    context,
                    out.addressOf(0).reinterpret(),
                    outputSize.ptr,
                    input.addressOf(0).reinterpret(),
                    dataInput.size.toULong()
                ) != 1
            ) {
                throw RuntimeException(
                    message = "Unable to decrypt data",
                    cause = OpenSSLException.create()
                )
            }
        }
        output.copyOf(outputSize.value.toInt())
    }
}

/**
 * This function creates an internal cipher closure by the specified values. The internal cipher is completely based on
 * OpenSSL. This function can be used by other developers to increase the functionality of the API for their own needs.
 *
 * @param isBlockCipher Whether this cipher is a block cipher or not
 * @param getCipher     Closure to acquire the cipher as EVP_CIPHER
 * @returns             The OTHER encryption/decryption cipher closure
 *
 * TODO: Add support for AAD
 *
 * @author Cedric Hammes
 * @since  27/09/2024
 */
@InternalKryptonAPI
fun symmetricCipher(
    isBlockCipher: Boolean,
    getCipher: (Key, CipherParameters) -> CPointer<EVP_CIPHER>?
): (CipherParameters, ByteArray, ByteArray?) -> ByteArray = { parameters, data, _ ->
    val key = parameters.key
    if (key.type != Key.Type.OTHER || key.body !is Key.KeyBody.DataKeyBody) {
        throw InitializationException("The key type '${key.type}' is not supported")
    }

    withFree {
        val context = EVP_CIPHER_CTX_new().checkNotNull().freeAfter(::EVP_CIPHER_CTX_free)
        val keyPointer = memScoped {
            // Acquire key pointer
            val keyPointer = allocPointerTo<BUF_MEM>()
            if (BIO_ctrl(key.body.data, BIO_C_GET_BUF_MEM_PTR, 0, keyPointer.ptr).toLong() != 1L) {
                throw InitializationException("Unable to get key memory", OpenSSLException.create())
            }
            keyPointer.pointed.checkNotNull().data.checkNotNull().reinterpret<UByteVar>()
        }

        initializeCipher(
            context = context,
            keyData = keyPointer,
            cipher = getCipher(key, parameters).checkNotNull().freeAfter(::EVP_CIPHER_free),
            parameters = parameters,
            init = if (parameters.mode == Cipher.Mode.ENCRYPT) ::EVP_EncryptInit else ::EVP_DecryptInit
        )
        doCipherOperation(
            context = context,
            isBlockCipher = isBlockCipher,
            dataInput = data,
            update = if (parameters.mode == Cipher.Mode.ENCRYPT) ::EVP_EncryptUpdate else ::EVP_DecryptUpdate,
            finalize = if (parameters.mode == Cipher.Mode.ENCRYPT) ::EVP_EncryptFinal else ::EVP_DecryptFinal
        )
    }
}

/**
 * This function is a wrapper around the initialization of a OpenSSL cipher. This function is existent to reduce code
 * duplication in the internal cipher. This API is internal because the developer don't need it in any case.
 *
 * @param context    The OpenSSL cipher context
 * @param keyData    Pointer to the data of the key
 * @param cipher     The OpenSSL cipher
 * @param parameters The cipher parameters
 * @param init       The initializer function
 *
 * @author Cedric Hammes
 * @since  27/09/2024
 */
@InternalKryptonAPI
internal fun initializeCipher(
    context: CPointer<EVP_CIPHER_CTX>,
    keyData: CPointer<UByteVar>,
    cipher: CPointer<EVP_CIPHER>,
    parameters: CipherParameters,
    init: (CPointer<EVP_CIPHER_CTX>, CPointer<EVP_CIPHER>, CPointer<UByteVar>, CPointer<UByteVar>?) -> Int
) {
    // TODO: + GCM tag, CTR etc.
    if (parameters is CBCCipherParameters) {
        parameters.iv.usePinned { pinnedIV ->
            if (init(context, cipher, keyData, pinnedIV.addressOf(0).reinterpret()) != 1) {
                throw InitializationException(
                    message = "Unable to initialize internal cipher",
                    cause = OpenSSLException.create()
                )
            }
        }
    } else {
        if (init(context, cipher, keyData, null) != 1) {
            throw InitializationException(
                message = "Unable to initialize internal cipher",
                cause = OpenSSLException.create()
            )
        }

    }
}

/**
 * This function is a wrapper around the cryptographic encryption or decryption operation done with a cipher. This
 * function is existent to reduce code duplication in the internal cipher. This API is internal because the developer
 * don't need it in any case.
 *
 * @param context       The OpenSSL cipher context
 * @param isBlockCipher Whether the current cipher is a block cipher or not
 * @param dataInput     The input data to be encrypted
 * @param update        The OpenSSL cipher update function
 * @param finalize      The OpenSSL cipher finalize function
 * @return              The encrypted byte array (with padding if set)
 *
 * @author Cedric Hammes
 * @since  27/09/2024
 */
@InternalKryptonAPI
internal fun doCipherOperation(
    context: CPointer<EVP_CIPHER_CTX>,
    isBlockCipher: Boolean,
    dataInput: ByteArray,
    update: (CPointer<EVP_CIPHER_CTX>, CPointer<UByteVar>, CPointer<IntVar>, CPointer<UByteVar>, Int) -> Int,
    finalize: (CPointer<EVP_CIPHER_CTX>, CPointer<UByteVar>, CPointer<IntVar>) -> Int
): ByteArray = memScoped {
    val updateOutputSize = alloc<Int>(0)
    val finalizeOutputSize = alloc<Int>(0)
    ByteArray(dataInput.size + (if (isBlockCipher) EVP_CIPHER_CTX_get_block_size(context) else 0)).also {
        dataInput.usePinned { input ->
            it.usePinned { output ->
                if (update(
                        context,
                        output.addressOf(0).reinterpret(),
                        updateOutputSize.ptr,
                        input.addressOf(0).reinterpret(),
                        dataInput.size
                    ) != 1
                ) {
                    throw CipherException(
                        message = "Unable to update data in cipher",
                        cause = OpenSSLException.create()
                    )
                }

                if (finalize(
                        context,
                        output.addressOf(updateOutputSize.value).reinterpret(),
                        finalizeOutputSize.ptr,
                    ) != 1
                ) {
                    throw CipherException(
                        message = "Unable to finalize cipher operation",
                        cause = OpenSSLException.create()
                    )
                }

            }
        }
    }.copyOf(updateOutputSize.value + finalizeOutputSize.value)
}
