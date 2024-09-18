import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotest)
    alias(libs.plugins.dokka)
    id("maven-publish")
}

// TODO: Use OpenSSL on Windows x64, macOS (is it default installed on macOS and iOS?) and Linux (x64 and arm64). If
//       changed, perform change in the README.md file.

group = "io.karma.evince"
version = "${libs.versions.krypton.get()}.${System.getenv("CI_PIPELINE_IID")?: 0}"
val isCIEnvironment = System.getenv("CI")?.equals("true")?: false
if (!isCIEnvironment)
    logger.info("Gradle build script is currently running in non-CI environment")

kotlin {
    val kotlinJvmTarget = libs.versions.jvmTarget.get()
    jvmToolchain(kotlinJvmTarget.toInt())

    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
        optIn.add("kotlinx.cinterop.ExperimentalForeignApi")
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
    linuxX64 {
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            freeCompilerArgs.addAll(listOf("-linker-option", "--allow-shlib-undefined"))
        }

        compilations.all {
            cinterops {
                val libssl by creating
            }
        }
        binaries.sharedLib()
    }

    sourceSets {
        commonMain.dependencies {
            implementation(libs.okio)
            implementation(libs.bignum)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.bundles.kotest)
        }
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
