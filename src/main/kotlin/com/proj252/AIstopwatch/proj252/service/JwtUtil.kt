package com.proj252.AIstopwatch.proj252.service

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.env.Environment
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component

import java.util.*
import javax.crypto.SecretKey

@Component
object JwtUtil {

    @Value("\${jwt.secret}")
    private lateinit var SECRET_KEY: String

    private const val EXPIRATION_TIME = 86400000 // Token expiration time in milliseconds (24 hour)
    private val KEY: SecretKey = Keys.hmacShaKeyFor(SECRET_KEY.toByteArray())

    // Generates a JWT token for the specified username
    fun generateToken(username: String): String {
        val expiration = Date(System.currentTimeMillis() + EXPIRATION_TIME)
        return Jwts.builder()
            .setSubject(username)
            .setExpiration(expiration)
            .signWith(KEY, SignatureAlgorithm.HS512)
            .compact()
    }

    // Validates the specified JWT token and returns true if it is valid
    fun validateToken(token: String, userDetails: UserDetails): Boolean {
        return try {
            val claims = getClaimsFromToken(token)
            !claims.expiration.before(Date())
        } catch (ex: Exception) {
            false
        }
    }

    // Gets the username from the specified JWT token
    fun getUsernameFromToken(token: String): String? {
        return try {
            val claims = getClaimsFromToken(token)
            claims.subject
        } catch (ex: Exception) {
            null
        }
    }

    // Parses the specified JWT token and returns the claims
    private fun getClaimsFromToken(token: String): Claims {
        return Jwts.parserBuilder()
            .setSigningKey(KEY)
            .build()
            .parseClaimsJws(token)
            .body
    }
}
