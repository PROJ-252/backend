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

    //이후 지속시간, 비밀키를 인코딩해서 세팅
    private const val EXPIRATION_TIME = 24*60*60*1000 // Token expiration time in milliseconds (24 hour)
    private val KEY: SecretKey = Keys.hmacShaKeyFor(SECRET_KEY.toByteArray())

    //JWT 토큰 생성함수(user_id를 입력값으로 받는다) => String
    fun generateToken(userDetails: UserDetails): String {
        val claims: Map<String, Any> = mapOf(
            "sub" to userDetails.username,
            "iat" to Date(),
            "exp" to Date(System.currentTimeMillis() + EXPIRATION_TIME),
            "userDetails" to userDetails
        )

        //expiration = Date(현재시간 + 지속시간)
        val expiration = Date(System.currentTimeMillis() + EXPIRATION_TIME)
        //Jwts.builder(): Jwt를 생성한다.
        return Jwts.builder()
            .setClaims(claims)
            //비밀키와 사인 알고리즘을 명시함을 명시
            .signWith(KEY, SignatureAlgorithm.HS512)
            //Jwt를 String으로 바꿈으로써 http에 담겨 전송될 수 있도록 구성
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
