package com.proj252.AIstopwatch.proj252.service

import com.proj252.AIstopwatch.proj252.repository.SdjTmpReportRepo
import org.junit.jupiter.api.Test

import org.mockito.Mock
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest

@DataJpaTest
//pass
class StopwatchServiceTest {

    @Mock
    lateinit var stopwatchRepo: SdjTmpReportRepo

    lateinit var stopwatchService: StopwatchService

    @Test
    fun getStopwatch() {
    }

    @Test
    fun runStopwatch() {
    }

    @Test
    fun pauseStopwatch() {
    }

    @Test
    fun warnStopwatch() {
    }

    @Test
    fun saveStopwatch() {
    }
}