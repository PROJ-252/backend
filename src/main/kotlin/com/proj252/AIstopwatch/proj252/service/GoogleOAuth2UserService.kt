package com.proj252.AIstopwatch.proj252.service

import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Service
import org.springframework.web.client.RestTemplate

@Service
class GoogleOAuth2UserService : OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private val restTemplate = RestTemplate()

    override fun loadUser(userRequest: OAuth2UserRequest): OAuth2User {
        val userInfoUri = "https://www.googleapis.com/oauth2/v3/userinfo"
        val responseRaw = restTemplate.getForObject(userInfoUri, Map::class.java)
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_user_info_response"))
        val response: Map<String, Any> = responseRaw.map { (key, value) -> key.toString() to (value as? Any ?: "") }.toMap()
        val nickname = response["nickname"] as String?
        val authorities = mutableListOf(SimpleGrantedAuthority("ROLE_USER"))
        return User(nickname, "", authorities).let { SimpleOAuth2User(it, response) }
    }

    //일일이 코드로 풀어 쓸 수 있게 attributes를 풀었다.
    private class SimpleOAuth2User(
        private val user: User,
        private val attributes: Map<String,Any>
    ) : OAuth2User {

        override fun getName(): String = user.username

        override fun getAttributes(): Map<String, Any> = attributes

        override fun getAuthorities() = user.authorities
    }
}

