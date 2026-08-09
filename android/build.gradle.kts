plugins {
    alias(libs.plugins.android.library)
    // kotlin-android removed: AGP 9.0 has built-in Kotlin support
}

android {
    namespace = "com.shoesproxy"
    compileSdk = 35

    defaultConfig {
        minSdk = 21
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            // JNI .so files built by cargo-ndk / build-android.sh
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}
