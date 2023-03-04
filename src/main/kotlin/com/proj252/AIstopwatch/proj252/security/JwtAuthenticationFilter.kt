package com.proj252.AIstopwatch.proj252.security

import com.proj252.AIstopwatch.proj252.service.JwtUtil
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.web.filter.OncePerRequestFilter

class JwtAuthenticationFilter(
    private val jwtUtil: JwtUtil,
    private val userDetailsService: UserDetailsService
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        //헤더의 Authorization 부분을 불러와서 String값으로 저장한다.
        val authorizationHeader: String? = request.getHeader(HttpHeaders.AUTHORIZATION)

        //불러온 문자열 헤더가 null이 아니고, "Bearer "로 시작하는 경우에 한해서 다음 로직을 실행한다.
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            //"Bearer "를 제외한 부분을 토큰화한다
            val jwtToken: String = authorizationHeader.substring(7)
            //jwtUtil로직을 이용해서 jwtToken 문자열로부터 username을 추출한다.
            val username: String? = jwtUtil.getUsernameFromToken(jwtToken)
            //추출한 사용자 명이 null이 아니고, SecurityContextHolder라는
            //(Spring Security에서 auth로직이 실행되면 자동으로 부여하는 context)가 로그인 맥락을 가지지 않을 때, 아래의 로직을 실행한다.
            if (username != null && SecurityContextHolder.getContext().authentication == null) {
                //userDetailService로 DB로부터 불러온 정보를 UserDetails 포맷에 맞게 담는다.
                val userDetails: UserDetails = userDetailsService.loadUserByUsername(username)
                //jwtUtil의 토큰비교로직으로 userDetails와 받아 온 jwtToken이 일치하는 경우 아래의 로직을 실행한다.
                if (jwtUtil.validateToken(jwtToken, userDetails)) {
                    //UsernamePasswordAuthenticationToken이라는
                    //(입력받은 username과 password를 통해 auth를 다루는 객체)에다가
                    //principal(id) - username / email 입력 or userDetails
                    //credentials - password 입력
                    //authorities - authorities 입력(생략가능)
                    val authenticationToken = UsernamePasswordAuthenticationToken(
                        userDetails.username,
                        userDetails.password,
                        userDetails.authorities
                    )
                    //추가한 UsernamePasswordAuthenticationToken.details는 요청등에서 담고 있는 detail정보에 대해 추가로 알려주는 것
                    // WebAuthenticationDetailsSource라는
                    //Web auth 과정의 여러것을 포함한 정보를 제공한다.(ip, session ID, ...)것의 디테일 request로 부터 빌드해서 수정한다.
                    authenticationToken.details = WebAuthenticationDetailsSource().buildDetails(request)

                    // SecurityContextHolder가 로그인 했다는 맥락을 가지게해준다.
                    SecurityContextHolder.getContext().authentication = authenticationToken
                }else{
                    print("일치안해요~")
                }
            }
        }

        filterChain.doFilter(request, response)
    }
}
