package com.proj252.AIstopwatch.proj252.dto.auth

data class RegisterDto(
    val accountId: String,
    val nickname: String,
    val password: String
)