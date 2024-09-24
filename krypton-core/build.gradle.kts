import de.undercouch.gradle.tasks.download.Download
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.konan.target.KonanTarget
import java.net.URI
import java.net.URLConnection
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.absolutePathString

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotest)
    alias(libs.plugins.dokka)
    alias(libs.plugins.download)
    id("maven-publish")
}

group = "io.karma.evince"
version = "${libs.versions.krypton.get()}.${System.getenv("CI_PIPELINE_IID") ?: 0}"

val buildFolder: Path = layout.buildDirectory.asFile.get().toPath()
val isCIEnvironment = System.getenv("CI")?.equals("true") ?: false
if (!isCIEnvironment)
    logger.info("Gradle build script is currently running in non-CI environment")

// OpenSSL Binaries download
// https://gitlab.com/trixnity/trixnity/-/blob/main/build.gradle.kts?ref_type=heads#L17-L60
val opensslBinariesVersion = libs.versions.openssl.binaries.get()
val opensslBinariesFolder: Path = buildFolder.resolve("openssl").resolve(opensslBinariesVersion)
val downloadOpenSSLBinariesTask = tasks.create("downloadOpenSSLBinaries", Download::class.java) {
    src("https://gitlab.com/api/v4/projects/57407788/packages/generic/build/v$opensslBinariesVersion/build.zip")
    dest(opensslBinariesFolder.resolve("binaries.zip").toFile())
    overwrite(false)
    retries(10)
}

val extractOpenSSLBinariesTask = tasks.create("extractOpenSSLBinaries", Copy::class.java) {
    dependsOn(downloadOpenSSLBinariesTask)
    from(zipTree(opensslBinariesFolder.resolve("binaries.zip"))) {
        eachFile {
            relativePath = RelativePath(true, *relativePath.segments.drop(2).toTypedArray())
        }
    }
    into(opensslBinariesFolder)
}

// OpenSSL targets
// https://gitlab.com/trixnity/trixnity/-/blob/main/trixnity-crypto-core/build.gradle.kts?ref_type=heads#L16-L33
class OpenSSLTarget(target: KonanTarget, val targetFactory: KotlinMultiplatformExtension.() -> KotlinNativeTarget) {
    private val targetFolder: Path = opensslBinariesFolder.resolve(target.name)
    val libFile: Path = targetFolder.resolve("lib").resolve("libcrypto.a")
    val includeFolder: Path = targetFolder.resolve("include")
}

val openSSLTargets = listOf(
    OpenSSLTarget(KonanTarget.LINUX_X64) { linuxX64() },
    OpenSSLTarget(KonanTarget.MINGW_X64) { mingwX64() },
    OpenSSLTarget(KonanTarget.MACOS_X64) { macosX64() },
    OpenSSLTarget(KonanTarget.MACOS_ARM64) { macosArm64() },
    OpenSSLTarget(KonanTarget.IOS_X64) { iosX64() },
    OpenSSLTarget(KonanTarget.IOS_ARM64) { iosArm64() },
    OpenSSLTarget(KonanTarget.IOS_SIMULATOR_ARM64) { iosSimulatorArm64() },
)

// Build script begin
@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    val kotlinJvmTarget = libs.versions.jvmTarget.get()
    jvmToolchain(kotlinJvmTarget.toInt())
    
    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }
    
    // Configure native OpenSSL targets
    // https://gitlab.com/trixnity/trixnity/-/blob/main/trixnity-crypto-core/build.gradle.kts?ref_type=heads#L41-L65
    openSSLTargets.forEach { target ->
        target.targetFactory(this).apply {
            compilations {
                "main" {
                    // Add CInterop for OpenSSL
                    cinterops {
                        val libopenssl by creating {
                            defFile("src/opensslMain/cinterop/libopenssl.def")
                            packageName("io.karma.evince.krypton.internal.openssl")
                            includeDirs(target.includeFolder)
                            tasks.named(interopProcessingTaskName) {
                               dependsOn(extractOpenSSLBinariesTask)
                            }
                        }
                    }
                }
            }
            compilerOptions {
                freeCompilerArgs.addAll("-include-binary", target.libFile.absolutePathString())
            }
        }
    }
    
    jvm {
        testRuns["test"].executionTask {
            useJUnitPlatform()
        }
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            jvmTarget.set(JvmTarget.valueOf("JVM_$kotlinJvmTarget"))
        }
    }
    
    sourceSets {
        all {
            languageSettings.optIn("kotlinx.cinterop.UnsafeNumber")
            languageSettings.optIn("kotlinx.cinterop.ExperimentalForeignApi")
        }
        
        val commonMain by getting {
            dependencies {
                implementation(libs.okio)
                implementation(libs.bignum)
            }
        }
        
        val opensslMain by creating {
            dependsOn(commonMain)
        }
        val linuxX64Main by getting {
            dependsOn(opensslMain)
        }
        val mingwX64Main by getting {
            dependsOn(opensslMain)
        }
        val macosX64Main by getting {
            dependsOn(opensslMain)
        }
        val macosArm64Main by getting {
            dependsOn(opensslMain)
        }
        val iosX64Main by getting {
            dependsOn(opensslMain)
        }
        val iosArm64Main by getting {
            dependsOn(opensslMain)
        }
        val iosSimulatorArm64Main by getting {
            dependsOn(opensslMain)
        }
        
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.bundles.kotest)
        }
        
        // Configure JVM source sets
        jvmMain.dependencies {
            implementation(libs.bouncycastle)
        }
        jvmTest.dependencies {
            implementation(libs.kotest.junit.runner)
        }
    }
}

publishing {
    val dokkaJar by tasks.registering(Jar::class) {
        from(tasks.dokkaHtml.flatMap { it.outputDirectory })
        archiveClassifier.set("javadoc")
        dependsOn(tasks.dokkaHtml)
    }
    
    publications.configureEach {
        if (this !is MavenPublication)
            return@configureEach
        
        pom {
            name = project.name
            description = "Krypton is a library that implements the cryptographic primitives into Kotlin"
            url = "https://git.karmakrafts.dev/kk/evince-project/krypton"
            licenses {
                license {
                    name = "Apache License, version 2.0"
                    url = "https://www.apache.org/licenses/LICENSE-2.0"
                }
            }
            developers {
                developer {
                    id = "cach30verfl0w"
                    name = "Cedric Hammes"
                    email = "cach30verfl0w@gmail.com"
                    roles = listOf("Lead Developer")
                    timezone = "Europe/Berlin"
                }
            }
            scm {
                url.set("https://git.karmakrafts.dev/kk/evince-project/krypton")
            }
        }
        
        if (isCIEnvironment)
            artifact(dokkaJar)
    }
}
