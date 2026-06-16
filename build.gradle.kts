plugins {
    kotlin("jvm") version "2.0.10" apply false
    id("io.gitlab.arturbosch.detekt") version "1.23.7" apply false
}

allprojects {
    group = "com.jasmin.security"
    version = "0.1.0-SNAPSHOT"
    repositories { mavenCentral() }
}

subprojects {
    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "io.gitlab.arturbosch.detekt")

    val detektVersion = "1.23.7"

    extensions.configure<JavaPluginExtension> {
        toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
    }

    extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
        compilerOptions { freeCompilerArgs.addAll("-Xjsr305=strict") }
    }

    configurations.all {
        exclude(group = "org.slf4j", module = "slf4j-simple")
    }
    configurations.named("testRuntimeClasspath") {
        exclude(group = "org.jetbrains.kotlin", module = "kotlin-main-kts")
    }

    dependencies {
        "compileOnly"("io.gitlab.arturbosch.detekt:detekt-api:$detektVersion")
        "detektPlugins"("io.gitlab.arturbosch.detekt:detekt-formatting:$detektVersion")
        "testImplementation"("io.gitlab.arturbosch.detekt:detekt-test:$detektVersion")
        "testImplementation"("org.assertj:assertj-core:3.26.3")
        "testImplementation"("org.junit.jupiter:junit-jupiter:5.11.0")
        "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
    }

    tasks.withType<Test> { useJUnitPlatform() }

    extensions.configure<io.gitlab.arturbosch.detekt.extensions.DetektExtension> {
        config.setFrom(rootProject.files("config/detekt/detekt.yml"))
        buildUponDefaultConfig = true
        source.setFrom("src/main/kotlin", "src/test/kotlin")
    }

    tasks.withType<io.gitlab.arturbosch.detekt.Detekt>().configureEach {
        reports {
            html.required.set(true)
            sarif.required.set(true)
        }
        jvmTarget = "21"
    }
}
