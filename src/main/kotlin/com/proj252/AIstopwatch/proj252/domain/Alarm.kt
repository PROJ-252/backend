package com.proj252.AIstopwatch.proj252.domain

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.JoinColumn
import jakarta.persistence.OneToOne
import lombok.Data
import lombok.Getter
import lombok.NoArgsConstructor
import lombok.NonNull
import lombok.RequiredArgsConstructor
import lombok.Setter

@Entity
data class Alarm(
    @Id
    @OneToOne @JoinColumn(name = "user_id")
    val user:User,

    @Column(name = "ison")
    var ison: Int,
    @Column(name = "ringtone_name")
    var ringtoneName: String
)