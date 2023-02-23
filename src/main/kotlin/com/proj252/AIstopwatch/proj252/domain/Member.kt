package com.proj252.AIstopwatch.proj252.domain

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.JoinColumn
import jakarta.persistence.OneToOne

@Entity
data class Member(
    @Id
    val id: String,

    @Column
    val password: String,

    @OneToOne
    @JoinColumn(name = "userId")
    val customUser:CustomUser
)