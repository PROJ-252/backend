package com.proj252.AIstopwatch.proj252.security

import com.proj252.AIstopwatch.proj252.service.JwtUtil
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter


@Configuration
@EnableWebSecurity
class SecurityConfig(val jwtUtil: JwtUtil, val userDetailsService: UserDetailsService) {

    @Bean
    public fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter::class.java)
            .authorizeHttpRequests()
                .requestMatchers("/calendar/**").authenticated()
                .anyRequest().permitAll()
                .and()
            .formLogin()
                .loginPage("/signin")
                .defaultSuccessUrl("/singin-success")
                .failureForwardUrl("/signin")
                .permitAll()
                .and()
            .logout()
                .logoutUrl("/signout-success")
                .logoutSuccessUrl("/stopwatch")
                .permitAll()

//            .oauth2Login()
//            .loginPage("/login") //!!로그인이 이뤄질 페이지 명시
//            .userInfoEndpoint()
//            .userService(GoogleOAuth2UserService())
//            .and()
//            .successHandler(OAuth2LoginSuccessHandler())

        return http.build()
    }

    @Bean
    fun jwtAuthenticationFilter(): JwtAuthenticationFilter{
        return JwtAuthenticationFilter(jwtUtil, userDetailsService)
    }
}