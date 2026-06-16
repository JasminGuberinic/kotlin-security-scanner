package com.jasmin.security.example

import java.security.MessageDigest
import java.util.Random

/**
 * Example file demonstrating vulnerabilities that Detekt security rules catch.
 * DO NOT use these patterns in production code.
 */
@Suppress("ALL")
object VulnerableExamples {

    // VULN: HardcodedCredentials
    private val password = "supersecret123"
    private val apiKey = "sk-prod-abc123xyz"
    private val dbPassword = "myDbP@ssw0rd"

    // VULN: InsecureRandom — not cryptographically secure
    fun generateToken(): Int {
        val random = Random()
        return random.nextInt(100000)
    }

    // VULN: SqlInjection — string interpolation
    fun findUser(username: String): String {
        return "SELECT * FROM users WHERE username = '$username'"
    }

    // VULN: SqlInjection — string concatenation
    fun deleteUser(userId: String): String {
        return "DELETE FROM users WHERE id = " + userId
    }

    // VULN: ForbiddenMethodCall — MD5 is broken
    fun hashPassword(pwd: String): ByteArray {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(pwd.toByteArray())
    }

    // VULN: ForbiddenMethodCall — SHA-1 is broken
    fun hashData(data: String): ByteArray {
        val md = MessageDigest.getInstance("SHA-1")
        return md.digest(data.toByteArray())
    }

    // SAFE — how to do it correctly
    fun safeToken(): Int {
        val random = java.security.SecureRandom()
        return random.nextInt(100000)
    }

    fun safeQuery(): String {
        return "SELECT * FROM users WHERE username = :username"
    }
}
