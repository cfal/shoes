plugins {
    alias(libs.plugins.android.library)
    // kotlin-android removed: AGP 9.0 has built-in Kotlin support
}

tasks.register<Sync>("dependencyNotices") {
    from("../THIRD_PARTY_NOTICES.md")
    from("../licenses") { into("licenses") }
    into(layout.buildDirectory.dir("generated/notices/META-INF/shoes"))
}

// AGP 9 rejects Provider values in SourceSet configuration.
android.sourceSets.getByName("main").resources.srcDir(
    layout.buildDirectory.dir("generated/notices").get().asFile,
)
tasks.named("preBuild").configure { dependsOn("dependencyNotices") }

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
