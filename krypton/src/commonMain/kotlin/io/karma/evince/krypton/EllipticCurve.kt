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
 * @author Cedric Hammes
 * @since  29/09/2024
 */
enum class EllipticCurve {
    PRIME192v3,
    PRIME192v2,
    PRIME192v1,
    PRIME256v1,
    PRIME239V3,
    PRIME239V2,
    PRIME239V1,
    SECT571R1,
    SECP224K1,
    SECP128R2,
    SECP160R2,
    SECP112R2,
    SECP384R1,
    SECP224R1,
    SECT193R1,
    SECT163R2,
    SECP160R1,
    SECP192K1,
    SECT131R1,
    SECT283R1,
    SECT163R1,
    SECT163K1,
    SECP521R1,
    SECP256K1,
    SECP160K1,
    SECT409K1,
    SECT283K1,
    SECT131R2,
    SECT239K1,
    SECT113R1,
    SECT571K1,
    SECT409R1,
    SECP128R1,
    SECP112R1,
    SECT113R2,
    BRAINPOOLP384T1,
    BRAINPOOLP160T1,
    BRAINPOOLP192T1,
    BRAINPOOLP256T1,
    BRAINPOOLP160R1,
    BRAINPOOLP512T1,
    BRAINPOOLP256R1,
    BRAINPOOLP384R1,
    BRAINPOOLP224T1,
    BRAINPOOLP320T1,
    BRAINPOOLP512R1,
    BRAINPOOLP192R1,
    BRAINPOOLP224R1,
    BRAINPOOLP320R1;

    override fun toString(): String = name.lowercase()
}
