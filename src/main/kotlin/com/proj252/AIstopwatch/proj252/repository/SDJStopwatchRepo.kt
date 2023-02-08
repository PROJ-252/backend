package com.proj252.AIstopwatch.proj252.repository

import com.proj252.AIstopwatch.proj252.domain.Report
import com.proj252.AIstopwatch.proj252.domain.TmpReport
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import java.util.*

interface SDJStopwatchRepo: JpaRepository<TmpReport,Long>,StopwatchRepo {
    @Query("select '*' from TmpReport where userId=:userId")
    override fun getByUserId(userId: Long): TmpReport?

    @Query("select totalTime from TmpReport where userId=:userId")
    override fun getTotalTime(userId: Long): Int

    @Query("update TmpReport set totalTime=:second where userId=:userId")
    override fun setTotalTime(userId: Long, second: Int)

//    @Query("UPDATE TmpReport SET total_time = :second where date = :userId")
    override fun setRunTime(userId: Long, dateTime: Date) {
        TODO("Not yet implemented")
    }
    override fun setPauseTime(userId: Long, dateTime: Date){
        TODO("Not yet implemented")
    }
    override fun setWarnTime(userId: Long, dateTime: Date) {
        TODO("Not yet implemented")
    }



    override fun createReport(userId: Long, date: Date): TmpReport {
        TODO("Not yet implemented")
    }

}