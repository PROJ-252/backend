package com.proj252.AIstopwatch.proj252.security

import com.proj252.AIstopwatch.proj252.service.GoogleOAuth2UserService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain


@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    public fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests()
                .requestMatchers("/calendar/**").authenticated()
                .anyRequest().permitAll()
                .and()
            .formLogin()
                .loginPage("/signin")
                .defaultSuccessUrl("/stopwatch")
                .failureForwardUrl("/signin")
                .permitAll()
                .and()
            .logout()
                .logoutUrl("/signout")
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
}