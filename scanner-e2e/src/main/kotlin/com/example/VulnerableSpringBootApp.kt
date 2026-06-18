package com.example

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

// ── A01 Broken Access Control ─────────────────────────────────────────────────

@RestController
@RequestMapping("/admin")
class AdminController {

    // VULNERABLE: no @PreAuthorize — any authenticated user can access admin endpoints [CWE-285]
    @GetMapping("/users")
    fun getAllUsers(): List<String> = listOf("alice", "bob")

    @GetMapping("/config")
    fun getSystemConfig(): Map<String, String> = mapOf("db.host" to "prod-db.internal")
}

// ── A02 Cryptographic Failures ────────────────────────────────────────────────

fun weakPasswordEncoder(): BCryptPasswordEncoder {
    // VULNERABLE: strength 4 is far below NIST minimum of 10 [CWE-916]
    return BCryptPasswordEncoder(4)
}

// ── A05 Security Misconfiguration ────────────────────────────────────────────

fun configure(http: HttpSecurity) {
    // VULNERABLE: CSRF protection disabled entirely [CWE-352]
    http.csrf().disable()

    // VULNERABLE: permits all origins — CORS wildcard [CWE-942]
    http.cors().configurationSource {
        org.springframework.web.cors.CorsConfiguration().apply {
            allowedOrigins = listOf("*")
        }
    }
}

// ── A03 Injection ─────────────────────────────────────────────────────────────

fun evaluateExpression(userInput: String): Any? {
    // VULNERABLE: SpEL injection — user controls expression [CWE-94]
    val parser = org.springframework.expression.spel.standard.SpelExpressionParser()
    return parser.parseExpression(userInput).getValue()
}

// ── A07 Identification and Authentication Failures ────────────────────────────

class DataSourceConfig {
    // VULNERABLE: hardcoded datasource password in source code [CWE-798]
    val datasourcePassword = "prodPassword123"

    fun rememberMe(http: HttpSecurity) {
        // VULNERABLE: hardcoded remember-me key — predictable token [CWE-798]
        http.rememberMe().key("hardcoded-remember-me-secret")
    }
}

// ── A09 Security Logging ──────────────────────────────────────────────────────

fun configureLogging() {
    // VULNERABLE: SQL logging in production leaks schema/data [CWE-532]
    System.setProperty("spring.jpa.show-sql", "true")
}

// ── A10 SSRF ──────────────────────────────────────────────────────────────────

@RestController
class ProxyController {
    // VULNERABLE: RestTemplate with user-controlled URL [CWE-918]
    @PostMapping("/fetch")
    fun fetch(url: String): String {
        val client = org.springframework.web.client.RestTemplate()
        return client.getForObject(url, String::class.java) ?: ""
    }
}
