package com.proj252.AIstopwatch.proj252.service

import com.proj252.AIstopwatch.proj252.domain.TmpReport
import com.proj252.AIstopwatch.proj252.repository.SdjTmpReportRepo
import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*
import org.mockito.Mockito.mock
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.transaction.annotation.Transactional
import java.util.*

@SpringBootTest
@Transactional
class StopwatchServiceTest {


    val tmpReportRepo: SdjTmpReportRepo = mock(SdjTmpReportRepo::class.java)
    val stopwatchService: StopwatchService = StopwatchService(tmpReportRepo)

    @Test
    fun 총시간반환(){
        var totalTime: Int
        totalTime = stopwatchService.getTotalTime(0, Date())
        print("this is "+totalTime+" ////")
    }

    @Test
    fun 실행시실행시간저장() {
        var date: Date = Date()
        stopwatchService.runStopwatch(0,date)
        print("maybe failed -- Date://"+date+"////////")
    }

    @Test
    fun 멈춤시멈춤시간저장() {
        var date: Date = Date()
        stopwatchService.pauseStopwatch(0,date)
        print("maybe failed -- Date://"+date+"////////")
    }

    @Test
    fun 경고시경고시간저장() {
        var date: Date = Date()
        stopwatchService.warnStopwatch(0,date)
        print("maybe failed -- Date://"+date+"////////")
    }

    @Test
    fun 스톱워치동기화() {
        stopwatchService.saveStopwatch(0, Date(), 20)
    }
}