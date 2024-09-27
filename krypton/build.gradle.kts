import de.undercouch.gradle.tasks.download.Download
import org.gradle.internal.os.OperatingSystem
import org.jetbrains.dokka.gradle.DokkaTask
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.konan.target.KonanTarget
import java.nio.file.Path
import kotlin.io.path.absolutePathString

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotest)
    alias(libs.plugins.dokka)
    alias(libs.plugins.download)
    id("maven-publish")
    idea
    eclipse
}

group = "io.karma.evince"
version = "${libs.versions.krypton.get()}.${System.getenv("CI_PIPELINE_IID") ?: 0}"

val buildFolder: Path = layout.buildDirectory.asFile.get().toPath()
val isCIEnvironment = System.getenv("CI")?.equals("true") ?: false
if (!isCIEnvironment)
    logger.info("Gradle build script is currently running in non-CI environment")

// Set html documentation output folder for dokkaHtml task to docs web server's folder when running in CI environment
if (isCIEnvironment) {
    tasks.named<DokkaTask>("dokkaHtml").configure {
        outputDirectory.set(File("/var/www/docs/krypton-core"))
    }
}

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
class OpenSSLTarget(
    target: KonanTarget,
    additionalLibraries: List<Path> = emptyList(),
    val targetFactory: KotlinMultiplatformExtension.() -> KotlinNativeTarget
) {
    private val targetFolder: Path = opensslBinariesFolder.resolve(target.name)
    private val libFile: Path = targetFolder.resolve("lib").resolve("libcrypto.a")
    
    val includeFolder: Path = targetFolder.resolve("include")
    val libraries: List<String> = mutableListOf(libFile).also { it.addAll(additionalLibraries) }
        .map { it.absolutePathString() }
}

val openSSLTargets = mutableListOf(
    OpenSSLTarget(KonanTarget.LINUX_X64) { linuxX64() },
    OpenSSLTarget(KonanTarget.MACOS_X64) { macosX64() },
    OpenSSLTarget(KonanTarget.MACOS_ARM64) { macosArm64() },
    OpenSSLTarget(KonanTarget.IOS_X64) { iosX64() },
    OpenSSLTarget(KonanTarget.IOS_ARM64) { iosArm64() },
    OpenSSLTarget(KonanTarget.IOS_SIMULATOR_ARM64) { iosSimulatorArm64() },
)

// Windows target
val mingwLibFolder: Path = if (OperatingSystem.current().isWindows) {
    Path.of(System.getProperty("user.home")).resolve(".konan/dependencies/msys2-mingw-w64-x86_64-2/x86_64-w64-mingw32/lib")
} else {
    Path.of("/usr/x86_64-w64-mingw32/lib")
}

// Add Windows target with libcrypt32 statically linked
logger.info("MinGW x86_64 found, add target")
openSSLTargets.add(OpenSSLTarget(KonanTarget.MINGW_X64, listOf(mingwLibFolder.resolve("libcrypt32.a"))) { mingwX64() })

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
                for (library in target.libraries) {
                    freeCompilerArgs.addAll("-include-binary", library)
                }
            }
        }
    }
    
    js {
        browser {
            testTask {
                useKarma {
                    useFirefoxHeadless()
                }
            }
        }
        nodejs {
            testTask {
                useMocha()
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
            languageSettings.optIn("io.karma.evince.krypton.annotations.UncheckedKryptonAPI")
            languageSettings.optIn("io.karma.evince.krypton.annotations.InternalKryptonAPI")
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
    
    repositories {
        maven {
            url = uri("https://git.karmakrafts.dev/api/v4/projects/303/packages/maven")
            name = "KarmaKrafts"
            credentials(HttpHeaderCredentials::class) {
                name = if (isCIEnvironment) "Job-Token" else "Private-Token"
                value = if (isCIEnvironment) System.getenv("CI_JOB_TOKEN") else
                    findProperty("krypton_ci_token").toString()
            }
            authentication {
                create("header", HttpHeaderAuthentication::class)
            }
            
        }
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
