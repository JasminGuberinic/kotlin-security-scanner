plugins {
	kotlin("jvm") version "2.0.10"
	kotlin("plugin.spring") version "2.0.10"
	id("org.springframework.boot") version "3.5.0"
	id("io.spring.dependency-management") version "1.1.7"
	kotlin("plugin.jpa") version "2.0.10"
	id("io.gitlab.arturbosch.detekt") version "1.23.7"
}

group = "com.jasmin.security"
version = "0.0.1-SNAPSHOT"
description = "Detekt security rules for Kotlin Spring Boot"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(21)
	}
}

repositories {
	mavenCentral()
}

configurations.all {
	exclude(group = "org.slf4j", module = "slf4j-simple")
}

configurations.testRuntimeClasspath {
	exclude(group = "org.jetbrains.kotlin", module = "kotlin-main-kts")
}

dependencies {
	implementation("org.springframework.boot:spring-boot-starter-data-jpa")
	implementation("org.springframework.boot:spring-boot-starter-security")
	implementation("org.springframework.boot:spring-boot-starter-validation")
	implementation("org.springframework.boot:spring-boot-starter-web")
	implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
	implementation("org.jetbrains.kotlin:kotlin-reflect")
	runtimeOnly("com.h2database:h2")
	testImplementation("org.springframework.boot:spring-boot-starter-test")
	testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
	testImplementation("org.springframework.security:spring-security-test")
	testRuntimeOnly("org.junit.platform:junit-platform-launcher")
	testImplementation("io.gitlab.arturbosch.detekt:detekt-test:1.23.7")

	compileOnly("io.gitlab.arturbosch.detekt:detekt-api:1.23.7")
	detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:1.23.7")
}

detekt {
	toolVersion = "1.23.7"
	config.setFrom(files("config/detekt/detekt.yml"))
	buildUponDefaultConfig = true
	allRules = false
	source.setFrom(
		"src/main/kotlin",
		"src/test/kotlin"
	)
}

tasks.withType<io.gitlab.arturbosch.detekt.Detekt>().configureEach {
	reports {
		html.required.set(true)
		xml.required.set(true)
		sarif.required.set(true)
	}
	jvmTarget = "21"
}

tasks.withType<io.gitlab.arturbosch.detekt.DetektCreateBaselineTask>().configureEach {
	jvmTarget = "21"
}

kotlin {
	compilerOptions {
		freeCompilerArgs.addAll("-Xjsr305=strict")
	}
}

allOpen {
	annotation("jakarta.persistence.Entity")
	annotation("jakarta.persistence.MappedSuperclass")
	annotation("jakarta.persistence.Embeddable")
}

tasks.withType<Test> {
	useJUnitPlatform()
}
