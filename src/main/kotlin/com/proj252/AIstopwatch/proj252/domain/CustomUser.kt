package com.proj252.AIstopwatch.proj252.domain

import jakarta.persistence.*
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User

@Entity
data class CustomUser(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    val userId: Long? = null,

    @Column(name = "nickname")
    private var nickname: String,

    @OneToOne(mappedBy = "customUser", cascade = [CascadeType.ALL])
    private val tmpReport: TmpReport? = null,
    @OneToOne(mappedBy="customUser", cascade = [CascadeType.REMOVE, CascadeType.DETACH, CascadeType.MERGE, CascadeType.REFRESH])
    private val member: Member? = null,
    @OneToOne(mappedBy = "customUser", cascade = [CascadeType.ALL])
    private val alarm: Alarm? = null
){

    fun toUser(): User{
        return User(
            nickname,
            "",
            mutableListOf(SimpleGrantedAuthority("ROLE_USER"))
        )
    }
}