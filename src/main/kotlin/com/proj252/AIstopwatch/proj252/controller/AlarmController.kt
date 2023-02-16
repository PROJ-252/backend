package com.proj252.AIstopwatch.proj252.controller

import com.proj252.AIstopwatch.proj252.dto.stopwatch.AlarmDto
import com.proj252.AIstopwatch.proj252.service.AlarmService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.bind.annotation.CookieValue
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.util.*

@RestController
@RequestMapping("alarm")
class AlarmController {

    private final var alarmService: AlarmService

    @Autowired
    constructor(alarmService: AlarmService){
        this.alarmService = alarmService
    }
    @PostMapping("/setting")
    fun setAlarm(@RequestBody alarmDto: AlarmDto, @CookieValue userId: Long){
        alarmService.setAlarm(userId, alarmDto.ison, alarmDto.ringtone)
    }
    @GetMapping
    fun getAlarm(@CookieValue userId: Long): AlarmDto{
        return alarmService.getAlarm(userId)
    }

}
