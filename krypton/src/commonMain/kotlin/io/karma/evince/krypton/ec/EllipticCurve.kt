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

package io.karma.evince.krypton.ec

import io.karma.evince.krypton.Platform

/**
 * This enum contains all by-default supported elliptic curves for the usage with elliptic curve based algorithms like
 * ECDSA or ECDH. These curves are standardized curves like the brainpool curves or the ANSI X9.62 curves.
 *
 * @author Cedric Hammes
 * @since  10/09/2024
 *
 * @see [Standard curve database](https://neuromancer.sk/std/)
 */
enum class EllipticCurve(private val literal: String, val bits: Int, internal val supportedPlatforms: Array<Platform>) {
    P256("P-256", 256, Platform.entries.toTypedArray()),
    P384("P-384", 384, Platform.entries.toTypedArray()),
    P521("P-521", 512, Platform.entries.toTypedArray()),
    PRIME192V1("prime192v1", 192, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    PRIME192V2("prime192v2", 192, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    PRIME192V3("prime192v3", 192, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    PRIME239V1("prime239v1", 239, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    PRIME239V2("prime239v2", 239, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    PRIME239V3("prime239v3", 239, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    PRIME256V1("prime256v1", 256, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P160T1("brainpoolP160t1", 160, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P192T1("brainpoolP192t1", 192, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P224T1("brainpoolP224t1", 224, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P256T1("brainpoolP256t1", 256, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P320T1("brainpoolP320t1", 320, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P384T1("brainpoolP384t1", 384, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P512T1("brainpoolP512t1", 512, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P160R1("brainpoolP160r1", 160, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P192R1("brainpoolP192r1", 192, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P224R1("brainpoolP224r1", 224, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P256R1("brainpoolP256r1", 256, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P320R1("brainpoolP320r1", 320, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P384R1("brainpoolP384r1", 384, Platform.entries.filter { !it.isJS() }.toTypedArray()),
    BRAINPOOL_P512R1("brainpoolP512r1", 512, Platform.entries.filter { !it.isJS() }.toTypedArray());
    
    override fun toString(): String = literal
}
