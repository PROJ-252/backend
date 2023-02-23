package com.proj252.AIstopwatch.proj252.domain

import jakarta.persistence.*
import lombok.NonNull
import java.util.Date

@Entity
data class TmpReport(
//Timed이 아니라 Int 타입 사용

    @Id @NonNull
    val date: Date,
    @OneToOne @JoinColumn(name = "user_id")
    val customUser: CustomUser,

    @Column(name = "total_time")
    var totalTime: Int,
    @Column(name = "goal_time")
    var goalTime: Int?,
    @Column(name = "goal_beginning")
    var goalBeginning: Date?,
    @Column(name = "goal_ending")
    var goalEnding: Date?,

    @OneToMany(mappedBy = "tmpReport", cascade = [CascadeType.ALL])
    var changeTimes: MutableList<TmpChangeTime>,
    @OneToMany(mappedBy = "tmpReport", cascade = [CascadeType.ALL])
    var warnTimes: MutableList<TmpWarnTime>
)