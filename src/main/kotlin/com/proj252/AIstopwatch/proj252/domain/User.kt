package com.proj252.AIstopwatch.proj252.domain

import jakarta.persistence.*

@Entity
data class User(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    val userId: Long? = null,

    @Column(name = "nickname")
    private var nickname: String,

    @OneToOne(mappedBy = "user", cascade = [CascadeType.ALL])
    private val tmpReport: TmpReport? = null,
    @OneToOne(mappedBy="user", cascade = [CascadeType.REMOVE, CascadeType.DETACH, CascadeType.MERGE, CascadeType.REFRESH])
    private val member: Member? = null,
    @OneToOne(mappedBy = "user", cascade = [CascadeType.ALL])
    private val alarm: Alarm? = null
)