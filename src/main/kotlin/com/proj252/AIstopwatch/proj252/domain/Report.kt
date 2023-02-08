package com.proj252.AIstopwatch.proj252.domain

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import lombok.AllArgsConstructor
import lombok.Data
import lombok.Getter
import lombok.NonNull
import java.sql.Time
import java.util.*

@Entity
@Getter //이미 만료된 리포트를 수정할 필요가 없다고 판단.
@AllArgsConstructor
class Report {

    @Id
    private lateinit var date: String
    @Column
    private var totalTime: Int = -1 // -1이면 초기화 오류상황 const를 하나 만들어서 처리해도 될듯 NONE
    @Column
    private var goalTime: Int? = null
    @Column
    private var goalBeginning: Date? = null
    @Column
    private var goalEnding: Date? = null
    @Column
    @NonNull
    private var userId: Long = -1


}