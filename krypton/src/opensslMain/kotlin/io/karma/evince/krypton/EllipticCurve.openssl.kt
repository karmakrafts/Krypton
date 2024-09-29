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

import io.karma.evince.krypton.internal.openssl.*

internal val EllipticCurve.nid: Int
    get() = when(this) {
        EllipticCurve.PRIME192v3 -> NID_X9_62_prime192v3
        EllipticCurve.PRIME192v2 -> NID_X9_62_prime192v2
        EllipticCurve.PRIME192v1 -> NID_X9_62_prime192v1
        EllipticCurve.PRIME256v1 -> NID_X9_62_prime256v1
        EllipticCurve.PRIME239V3 -> NID_X9_62_prime239v3
        EllipticCurve.PRIME239V2 -> NID_X9_62_prime239v2
        EllipticCurve.PRIME239V1 -> NID_X9_62_prime239v1
        EllipticCurve.SECT571R1 -> NID_sect571r1
        EllipticCurve.SECP224K1 -> NID_secp224k1
        EllipticCurve.SECP128R2 -> NID_secp128r2
        EllipticCurve.SECP160R2 -> NID_secp160r2
        EllipticCurve.SECP112R2 -> NID_secp112r2
        EllipticCurve.SECP384R1 -> NID_secp384r1
        EllipticCurve.SECP224R1 -> NID_secp224r1
        EllipticCurve.SECT193R1 -> NID_sect193r1
        EllipticCurve.SECT163R2 -> NID_sect163r2
        EllipticCurve.SECP160R1 -> NID_secp160r1
        EllipticCurve.SECP192K1 -> NID_secp192k1
        EllipticCurve.SECT131R1 -> NID_sect131r1
        EllipticCurve.SECT283R1 -> NID_sect283r1
        EllipticCurve.SECT163R1 -> NID_sect163r1
        EllipticCurve.SECT163K1 -> NID_sect163k1
        EllipticCurve.SECP521R1 -> NID_secp521r1
        EllipticCurve.SECP256K1 -> NID_secp256k1
        EllipticCurve.SECP160K1 -> NID_secp160k1
        EllipticCurve.SECT409K1 -> NID_sect409k1
        EllipticCurve.SECT283K1 -> NID_sect283k1
        EllipticCurve.SECT131R2 -> NID_sect131r2
        EllipticCurve.SECT239K1 -> NID_sect239k1
        EllipticCurve.SECT113R1 -> NID_sect113r1
        EllipticCurve.SECT571K1 -> NID_sect571k1
        EllipticCurve.SECT409R1 -> NID_sect409r1
        EllipticCurve.SECP128R1 -> NID_secp128r1
        EllipticCurve.SECP112R1 -> NID_secp112r2
        EllipticCurve.SECT113R2 -> NID_sect113r2
        EllipticCurve.BRAINPOOLP384T1 -> NID_brainpoolP384t1
        EllipticCurve.BRAINPOOLP160T1 -> NID_brainpoolP160t1
        EllipticCurve.BRAINPOOLP192T1 -> NID_brainpoolP192t1
        EllipticCurve.BRAINPOOLP256T1 -> NID_brainpoolP256t1
        EllipticCurve.BRAINPOOLP160R1 -> NID_brainpoolP160r1
        EllipticCurve.BRAINPOOLP512T1 -> NID_brainpoolP512t1
        EllipticCurve.BRAINPOOLP256R1 -> NID_brainpoolP256r1
        EllipticCurve.BRAINPOOLP384R1 -> NID_brainpoolP384r1
        EllipticCurve.BRAINPOOLP224T1 -> NID_brainpoolP224t1
        EllipticCurve.BRAINPOOLP320T1 -> NID_brainpoolP320t1
        EllipticCurve.BRAINPOOLP512R1 -> NID_brainpoolP512r1
        EllipticCurve.BRAINPOOLP192R1 -> NID_brainpoolP192r1
        EllipticCurve.BRAINPOOLP224R1 -> NID_brainpoolP224r1
        EllipticCurve.BRAINPOOLP320R1 -> NID_brainpoolP320r1
    }
