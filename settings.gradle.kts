dependencyResolutionManagement {
    repositories {
        mavenCentral()
        mavenLocal()
        google()
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots/") {
            name = "MavenCentralSnapshots"
            mavenContent { snapshotsOnly() }
        }
        maven("https://git.karmakrafts.dev/api/v4/projects/314/packages/maven")
    }
}

buildCache {
    local {
        directory = File(rootDir, ".gradle").resolve("buildcache")
    }
}

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots/") {
            name = "MavenCentralSnapshots"
            mavenContent { snapshotsOnly() }
        }
    }
}

include(":krypton")
rootProject.name = "krypton"
