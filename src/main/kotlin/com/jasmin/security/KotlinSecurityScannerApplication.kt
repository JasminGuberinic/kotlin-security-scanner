package com.jasmin.security

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class KotlinSecurityScannerApplication

@Suppress("SpreadOperator")
fun main(args: Array<String>) {
    runApplication<KotlinSecurityScannerApplication>(*args)
}
