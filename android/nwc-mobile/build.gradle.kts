plugins {
  id("com.android.library") version "9.3.2"
}

android {
  namespace = "org.nwc.mobile.android"
  compileSdk = 36

  defaultConfig {
    minSdk = 23
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
  }

  testOptions {
    unitTests.all {
      it.useJUnit()
    }
  }
}

kotlin {
  compilerOptions {
    allWarningsAsErrors = true
  }
}

dependencies {
  implementation("androidx.concurrent:concurrent-futures:1.1.0")
  implementation("androidx.work:work-runtime-ktx:2.11.2")
  implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

  testImplementation("junit:junit:4.13.2")
}

dependencyLocking {
  lockAllConfigurations()
}
