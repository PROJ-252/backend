package com.proj252.AIstopwatch.proj252.domain

import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.JoinColumn
import jakarta.persistence.ManyToOne
import lombok.NonNull
import java.util.*

@Entity
data class TmpWarnTime(
    @Id @NonNull
    private val track: Date,
    @ManyToOne @JoinColumn(name = "tmp_report_date")
    private val tmpReport: TmpReport

)