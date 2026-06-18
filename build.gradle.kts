plugins {
    kotlin("jvm") version "2.0.10" apply false
    id("io.gitlab.arturbosch.detekt") version "1.23.7" apply false
    id("com.vanniktech.maven.publish") version "0.29.0" apply false
}

allprojects {
    group = "io.github.jasminguberinic"
    version = "0.1.0"
    repositories { mavenCentral() }
}

// ── Root-level security tasks ──────────────────────────────────────────────────
//
// generateSecurityBaseline — snapshot current findings into config/detekt/security-baseline.xml.
//   Brownfield teams run this once to accept existing issues. Subsequent checkSecurity calls
//   only fail on *new* findings introduced after the snapshot.
//
// checkSecurity — run the full security scan with the active baseline.
//   New findings fail the build; baselined ones are silently skipped.

tasks.register("generateSecurityBaseline") {
    group = "security"
    description = "Snapshot current security findings as the baseline (new violations will still fail)."
    dependsOn(subprojects.map { "${it.path}:detektBaseline" })
    doLast {
        println("Security baseline written to config/detekt/security-baseline.xml")
        println("Commit this file so CI enforces only regressions, not pre-existing issues.")
    }
}

tasks.register("checkSecurity") {
    group = "security"
    description = "Security scan — only findings absent from the baseline cause a failure."
    dependsOn(subprojects.map { "${it.path}:detekt" })
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
        baseline = rootProject.file("config/detekt/security-baseline.xml")
    }

    tasks.withType<io.gitlab.arturbosch.detekt.Detekt>().configureEach {
        reports {
            html.required.set(true)
            sarif.required.set(true)
        }
        jvmTarget = "21"
    }

    // Shared POM metadata applied whenever a module opts into publishing
    pluginManager.withPlugin("com.vanniktech.maven.publish") {
        configure<com.vanniktech.maven.publish.MavenPublishBaseExtension> {
            publishToMavenCentral(com.vanniktech.maven.publish.SonatypeHost.CENTRAL_PORTAL)
            signAllPublications()
            pom {
                url = "https://github.com/JasminGuberinic/kotlin-security-scanner"
                inceptionYear = "2024"
                licenses {
                    license {
                        name = "Apache-2.0"
                        url = "https://www.apache.org/licenses/LICENSE-2.0"
                        distribution = "repo"
                    }
                }
                developers {
                    developer {
                        id = "JasminGuberinic"
                        name = "Jasmin Guberinic"
                        email = "jasmin.guberinic@gmail.com"
                    }
                }
                scm {
                    url = "https://github.com/JasminGuberinic/kotlin-security-scanner"
                    connection = "scm:git:git://github.com/JasminGuberinic/kotlin-security-scanner.git"
                    developerConnection =
                        "scm:git:ssh://git@github.com/JasminGuberinic/kotlin-security-scanner.git"
                }
            }
        }
    }
}
