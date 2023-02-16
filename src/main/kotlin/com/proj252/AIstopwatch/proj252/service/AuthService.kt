package com.proj252.AIstopwatch.proj252.service

import com.proj252.AIstopwatch.proj252.dto.auth.RegisterDto
import com.proj252.AIstopwatch.proj252.dto.auth.SigninDto
import org.springframework.stereotype.Service

@Service
class AuthService {
    public fun signin(signinDto: SigninDto, userId: Long){
        getAuthState(userId)
        connectAuth(signinDto)
    }
    public fun signout(userId: Long){
        getAuthState(userId)
        disconnectAuth()
    }
    public fun register(registerDto: RegisterDto, userId: Long){
        getAuthState(userId)
        validateDupId()
        registerMember(registerDto)
    }
    public fun unregister(userId: Long){
        getAuthState(userId)
        unregisterMember()
        signout(userId)
    }


    //Cookie를 바꾸는 로직을 구현하자.
    private fun getAuthState(userId: Long){

    }
    private fun connectAuth(signinDto: SigninDto){

    }
    private fun disconnectAuth(){

    }

    //OK 확인을 보내는 로직을 구현하자.
    private fun registerMember(registerDto: RegisterDto){

    }
    private fun unregisterMember(){

    }

    private fun validateDupId(){

    }

}