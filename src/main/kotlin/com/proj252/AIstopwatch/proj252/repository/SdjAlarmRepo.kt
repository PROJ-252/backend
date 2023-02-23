package com.proj252.AIstopwatch.proj252.repository

import com.proj252.AIstopwatch.proj252.domain.Alarm
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.*

@Repository
interface SdjAlarmRepo: JpaRepository<Alarm,Long> {
    @Override
    fun findByUserId(id: Long): Optional<Alarm>
}