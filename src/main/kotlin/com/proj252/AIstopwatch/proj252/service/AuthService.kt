package com.proj252.AIstopwatch.proj252.service

import com.proj252.AIstopwatch.proj252.domain.Member
import com.proj252.AIstopwatch.proj252.domain.CustomUser
import com.proj252.AIstopwatch.proj252.dto.auth.RegisterDto
import com.proj252.AIstopwatch.proj252.dto.auth.SigninDto
import com.proj252.AIstopwatch.proj252.repository.SdjMemberRepo
import com.proj252.AIstopwatch.proj252.repository.SdjUserRepo
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service

@Service
class AuthService {

    private lateinit var memberRepo: SdjMemberRepo
    private lateinit var userRepo:SdjUserRepo

    @Autowired
    //여기서 repo 갈아끼울 수 있음
    constructor(memberRepo: SdjMemberRepo, userRepo: SdjUserRepo){
        this.memberRepo = memberRepo
        this.userRepo = userRepo
    }
    public fun signin(signinDto: SigninDto, userId: Long){
        if(isConnecting(userId)){
            print("is Already SignIn") //400번대 에러만들기
        }else{
            validateAccount(signinDto)
            connectAuth(signinDto)
        }
    }
    public fun signout(userId: Long){
        if(isConnecting(userId)){
            disconnectAuth()
        }else{
            //400번대 에러만들기
        }
    }
    public fun register(registerDto: RegisterDto, userId: Long){
        if(isConnecting(userId)){
            print("is Already SignIn") //400번대 에러만들기
        }else{
            if(validateDupId(registerDto.accountId)){
                print("Member using this already is")
            }else{
                registerMember(registerDto)
            }
        }
    }
    public fun unregister(userId: Long){
        if(isConnecting(userId)){
            //find member - by userId
            unregisterMember(userId)
            signout(userId)
        }else{
            //400번대 에러만들기
        }
    }
    public fun useWithoutLogin(userId: Long){
        if(!isConnecting(userId)){
            //session Id 쿠키로 전달
            userRepo.save(CustomUser(nickname = "UNKNOWN"))
        }
    }


    //Cookie를 바꾸는 로직을 구현하자.
    private fun isConnecting(userId: Long):Boolean{
        return (userId != -1L)
    }
    private fun connectAuth(signinDto: SigninDto){
        //Cookie를 생성한 로그인 세션값으로 부여

    }
    private fun disconnectAuth(){
        //Cookie의 로그인 세션값 NONETOKEN으로 수정
    }

    //OK 확인을 보내는 로직을 구현하자.
    private fun validateAccount(signinDto: SigninDto):Boolean{
        val member: Member? = memberRepo.findMemberById(signinDto.accountId).orElse(null)

        return member != null
    }
    private fun registerMember(registerDto: RegisterDto){
        if(!memberRepo.existsMemberById(registerDto.accountId)){
            //User등록 후 User 반환
            val customUser: CustomUser = registerUser(registerDto.nickname)

            val member: Member = Member(
                id = registerDto.accountId,
                password = registerDto.password,
                customUser = customUser
            )

            memberRepo.save(member)
        }

    }
    private fun unregisterMember(userId: Long){
        memberRepo.deleteMemberByUser_UserId(userId)
    }

    private fun validateDupId(accountId: String): Boolean{
        return memberRepo.existsMemberById(accountId)
    }

    private fun registerUser(nickname: String): CustomUser{
        return userRepo.save(CustomUser(nickname = nickname))
    }

}