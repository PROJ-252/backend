package com.proj252.AIstopwatch.proj252.dto.stopwatch

import java.util.Date

data class StopwatchPauseDto(
    val date: Date,
    var pauseTime: Date
)