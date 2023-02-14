package com.proj252.AIstopwatch.proj252.repository

import com.proj252.AIstopwatch.proj252.domain.TmpReport
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.*

@Repository
interface SdjTmpReportRepo: JpaRepository<TmpReport,Date>{

    //get report by id&date
    @Override
    fun findTmpReportByUser_UserIdAndDate(userId: Long, date: Date): Optional<TmpReport>
    @Override
    fun existsTmpReportByUser_UserIdAndDate(userId: Long, date: Date): Boolean

}