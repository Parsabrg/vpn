import java.util.Base64
import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Release signing material, kept out of the repository: android/key.properties
// and the keystore it points at are both gitignored, so a clone has neither.
// Absent (CI, a fresh clone, any machine that is not the release machine) this
// stays null and the release build below falls back to debug signing rather
// than failing -- an unsigned-for-release build is still useful for checking
// that the app compiles, and only the release machine can produce a
// distributable one.
val keystoreProperties = Properties().apply {
    val file = rootProject.file("key.properties")
    if (file.exists()) {
        file.inputStream().use { load(it) }
    }
}
val hasReleaseSigning = keystoreProperties.getProperty("storeFile") != null

// A release build may carry the address of one deployment; if it does, that
// address must be https, or the build stops here with the fix in the message
// rather than shipping an app that sends credentials in the clear.
//
// Carrying none is the normal case: a generic build is paired with a
// deployment on first launch (lib/core/pairing/pairing.dart).
//
// Flutter hands dart-defines to Gradle base64-encoded and comma-separated.
val releaseRequested = gradle.startParameter.taskNames.any {
    it.contains("release", ignoreCase = true)
}
if (releaseRequested) {
    val dartDefines = (project.findProperty("dart-defines") as String?)
        ?.split(",")
        ?.filter { it.isNotBlank() }
        ?.map { encoded ->
            try {
                String(Base64.getDecoder().decode(encoded))
            } catch (error: IllegalArgumentException) {
                encoded
            }
        }
        .orEmpty()
    val apiBaseUrl = dartDefines
        .firstOrNull { it.startsWith("API_BASE_URL=") }
        ?.removePrefix("API_BASE_URL=")
    if (apiBaseUrl != null && !apiBaseUrl.startsWith("https://")) {
        throw GradleException(
            "API_BASE_URL must be https:// in a release build (got \"$apiBaseUrl\"). " +
                "Leave it out entirely for a generic build that is paired on first launch.",
        )
    }
}

android {
    namespace = "org.nebulavpn.nebula_mobile"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "org.nebulavpn.nebula_mobile"
        // Android 8.0 (API 26), the minimum supported version.
        minSdk = 26
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        // On-device tests install beside the everyday app instead of over it
        // (docs/runbooks/device-tests.md):
        //   flutter build apk -P nebula.applicationIdSuffix=.devicetest
        // Unset in every real build.
        (project.findProperty("nebula.applicationIdSuffix") as String?)?.let {
            applicationIdSuffix = it
        }
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            // The debug keystore is the one every Android SDK install ships,
            // with a published password, so signing a release with it means
            // anyone can build an APK the OS will accept as an update to this
            // one. For a VPN client holding credentials and carrying all of a
            // device's traffic, that is the signature check doing nothing at
            // all -- hence a real key, which only the release machine has.
            //
            // Falls back to debug signing when that key is absent so a clone
            // or CI can still build; such a build installs and runs, but is
            // not distributable.
            signingConfig = if (hasReleaseSigning) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
            // Beside Flutter's own rules: what native code finds by name.
            proguardFiles("proguard-rules.pro")
        }
    }

    // The Hysteria2 client (libhysteria.so) runs as an actual subprocess, as
    // badvpn's libtun2socks.so did before hev-socks5-tunnel replaced it
    // (ProcessBuilder against
    // a real file path under ApplicationInfo.nativeLibraryDir), not as a
    // JNI library loaded via System.loadLibrary -- but AGP's modern default
    // packaging mmaps native libraries directly out of the APK's zip instead
    // of extracting them to disk, so no such file ever exists at that path.
    // Confirmed live on a real device: connect() failed with "Cannot run
    // program .../lib/arm64/libtun2socks.so: No such file or directory".
    // Legacy packaging restores the old always-extract-to-disk behavior
    // these subprocess-spawning native libraries depend on.
    packaging {
        jniLibs {
            useLegacyPackaging = true

            // A build for one platform ships only that platform's native
            // libraries. `--target-platform` narrows Flutter's own engine but
            // not the plugins': the tunnel core, tun2socks and the Hysteria2
            // client came along for all three ABIs, so an arm64 build was 77MB
            // of which 44MB could never run on the phone installing it.
            //
            // Excluded here rather than with `ndk.abiFilters`, which the Flutter
            // plugin clears and refills, and rather than `--split-per-abi`,
            // which gives each ABI its own versionCode (1000 more per ABI).
            // Android refuses a lower code over a higher one, so installing a
            // split would rule out ever updating to the universal APK the
            // release page also offers.
            val abiForPlatform = mapOf(
                "android-arm" to "armeabi-v7a",
                "android-arm64" to "arm64-v8a",
                "android-x64" to "x86_64",
            )
            val targetPlatforms = (project.findProperty("target-platform") as String?)
                ?.split(",")
                ?.filter { it.isNotBlank() }
                .orEmpty()
            val onlyAbi = abiForPlatform[targetPlatforms.singleOrNull()]
            if (onlyAbi != null) {
                (abiForPlatform.values + listOf("x86", "armeabi"))
                    .filter { it != onlyAbi }
                    .forEach { abi -> excludes += "lib/$abi/**" }
            }
        }
    }
}

dependencies {
    // The official WireGuard Android embeddable tunnel library
    // (wireguard-go via JNI, behind a Kotlin Backend/Tunnel API) -- reuses
    // WireGuard's own real implementation rather than reimplementing the
    // protocol, matching how the Windows client shells out to the official
    // wireguard.exe rather than reimplementing it there either.
    implementation("com.wireguard.android:tunnel:1.0.20260102")
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
