package com.proj252.AIstopwatch.proj252.controller

import com.proj252.AIstopwatch.proj252.dto.auth.RegisterDto
import com.proj252.AIstopwatch.proj252.dto.auth.SigninDto
import com.proj252.AIstopwatch.proj252.dto.stopwatch.AlarmDto
import com.proj252.AIstopwatch.proj252.service.AuthService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("auth")
class AuthController {
    private val authService: AuthService

    @Autowired
    constructor(authService: AuthService){
        this.authService = authService
    }

    @PostMapping("/signin")
    fun signIn(@RequestBody signinDto: SigninDto, @CookieValue userId: Long){
        authService.signin(signinDto, userId)
    }
    @PostMapping("/signout")
    fun signOut(@CookieValue userId: Long){
        authService.signout(userId)
    }
    @PostMapping("/register")
    fun register(@RequestBody registerDto: RegisterDto, @CookieValue userId: Long){
        authService.register(registerDto, userId)
    }
    @PostMapping("/unregister")
    fun unregister(@CookieValue userId: Long){
        authService.unregister(userId)
    }

    @PostMapping("/without-login")
    fun withoutLogin(@CookieValue userId: Long){
        authService.useWithoutLogin(userId)
    }

}