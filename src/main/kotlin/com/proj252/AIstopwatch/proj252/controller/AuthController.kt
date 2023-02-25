package com.proj252.AIstopwatch.proj252.controller

import com.proj252.AIstopwatch.proj252.dto.auth.RegisterDto
import com.proj252.AIstopwatch.proj252.dto.auth.SigninDto
import com.proj252.AIstopwatch.proj252.dto.stopwatch.AlarmDto
import com.proj252.AIstopwatch.proj252.service.AuthService
import com.proj252.AIstopwatch.proj252.service.GoogleOAuth2UserService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.web.bind.annotation.*
import java.lang.ProcessBuilder.Redirect

@RestController
@RequestMapping("auth")
class AuthController{
    private val authService: AuthService
    private val oauth2UserService: GoogleOAuth2UserService

    @Autowired
    constructor(authService: AuthService, oauth2UserService: GoogleOAuth2UserService){
        this.authService = authService
        this.oauth2UserService = oauth2UserService
    }

    @GetMapping("/signin")
    fun signIn(@AuthenticationPrincipal oAuth2UserRequest: OAuth2UserRequest): ResponseEntity<String>{
        return if (oAuth2UserRequest != null) {
            ResponseEntity.ok("Alreay signed in")
        } else {
            ResponseEntity.ok("Alreay signed in")
            //redirection to /signin-success
        }
    }
    //GetMapping에서 리턴값은 뭘 의미하는가?

    @PostMapping("/signin-success")
    fun signInSuccess(@AuthenticationPrincipal oAuth2UserRequest: OAuth2UserRequest): String{
        val userDetails: OAuth2User = oauth2UserService.loadUser(oAuth2UserRequest)

        // Access user information
        val nickname = userDetails.name

        // Return success message
        return "SignIn success - $nickname!"
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