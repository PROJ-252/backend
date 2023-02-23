package com.proj252.AIstopwatch.proj252.domain

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.JoinColumn
import jakarta.persistence.MapsId
import jakarta.persistence.OneToOne

@Entity
data class Alarm(
    @Id
    @Column(name = "user_id", nullable = false)
    val userId: Long,

    @OneToOne @JoinColumn(name = "user_id")
    @MapsId
    val customUser:CustomUser,

    @Column(name = "ison")
    var ison: Int,
    @Column(name = "ringtone_name")
    var ringtoneName: String
)