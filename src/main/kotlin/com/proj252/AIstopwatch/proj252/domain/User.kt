package com.proj252.AIstopwatch.proj252.domain

import jakarta.persistence.*

@Entity
data class User(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    var userId: Long,

    @Column(name = "nickname")
    private var nickname: String?,

    @OneToOne(mappedBy = "user")
    private val tmpReport: TmpReport,
    @OneToOne(mappedBy="user")
    private val member: Member?,
    @OneToOne(mappedBy = "user")
    private val alarm: Alarm
)