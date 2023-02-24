package com.proj252.AIstopwatch.proj252.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Component

@Component
class OAuth2LoginSuccessHandler : AuthenticationSuccessHandler {

    @Autowired
    private lateinit var tokenEndpointClient: OAuth2AuthorizedClientService

    override fun onAuthenticationSuccess(request: HttpServletRequest, response: HttpServletResponse, authentication: Authentication) {
        val oauth2Authentication = authentication as OAuth2AuthenticationToken

        val authorizedClient = tokenEndpointClient.loadAuthorizedClient<OAuth2AuthorizedClient>(oauth2Authentication.authorizedClientRegistrationId, oauth2Authentication.name)

        // Use the authorized client to access the protected resource
        val accessToken = authorizedClient.accessToken

        // TODO: redirect the user to a protected page or display a success message & accessToken 넣어서 전달.

    }
}