package com.proj252.AIstopwatch.proj252.service

import com.proj252.AIstopwatch.proj252.repository.SdjAlarmRepo
import org.junit.jupiter.api.Test

import org.mockito.Mockito
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.transaction.annotation.Transactional

@SpringBootTest
@Transactional
class AlarmServiceTest {

    val alarmRepo: SdjAlarmRepo = Mockito.mock(SdjAlarmRepo::class.java)
    val alarmService: AuthService = AuthService(alarmRepo)

    @Test
    fun 알람음변경() {
        alarmService.setAlarm(0,1,"default")
        print("hi\n")
    }

    @Test
    fun getAlarm() {
        print(alarmService.getAlarm(0).ringtone+"hi\n")
    }
}