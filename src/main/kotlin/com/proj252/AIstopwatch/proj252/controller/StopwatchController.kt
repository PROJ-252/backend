package com.proj252.AIstopwatch.proj252.controller

import com.proj252.AIstopwatch.proj252.dto.stopwatch.StopwatchPauseDto
import com.proj252.AIstopwatch.proj252.dto.stopwatch.StopwatchRunDto
import com.proj252.AIstopwatch.proj252.dto.stopwatch.StopwatchSyncDto
import com.proj252.AIstopwatch.proj252.service.StopwatchService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.bind.annotation.CookieValue
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.util.*

@RestController
@RequestMapping("stopwatch")
class StopwatchController {

    private final var stopwatchService: StopwatchService

    @Autowired
    constructor(stopwatchService: StopwatchService){
        this.stopwatchService = stopwatchService
    }

    @PostMapping("/control/run")
    fun runStopwatch(@RequestBody stopwatchRunDto: StopwatchRunDto, @CookieValue userId: Long){
        stopwatchService.runStopwatch(userId, stopwatchRunDto.runTime)
    }
    @PostMapping("/control/pause")
    fun pauseStopwatch(@RequestBody stopwatchPauseDto: StopwatchPauseDto, @CookieValue userId: Long){
        stopwatchService.pauseStopwatch(userId, stopwatchPauseDto.pauseTime)
    }
    @PostMapping("/sync")
    fun syncStopwatch(@RequestBody stopwatchSyncDto: StopwatchSyncDto, @CookieValue userId: Long){
        stopwatchService.saveStopwatch(userId, stopwatchSyncDto.date, stopwatchSyncDto.time)
    }
    @GetMapping("/total")
    fun getTotalTime(@CookieValue userId: Long): Int{
        return stopwatchService.getTotalTime(userId, Date())
    }

}
