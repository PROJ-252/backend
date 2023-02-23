package com.proj252.AIstopwatch.proj252.security

import com.proj252.AIstopwatch.proj252.service.GoogleOAuth2UserService
import com.proj252.AIstopwatch.proj252.service.GoogleOAuthUserService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.stereotype.Service


@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    public fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http.authorizeHttpRequests()
            .anyRequest().authenticated()
            .and()
            .oauth2Login()
            .loginPage("/login") //!!로그인이 이뤄질 페이지 명시
            .userInfoEndpoint()
            .userService(GoogleOAuth2UserService())
            .and()
            .successHandler(oauth2AuthenticationSuccessHandler())


        return http.build()
    }
}