package com.proj252.AIstopwatch.proj252.controller

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.ObjectMapper
import com.proj252.AIstopwatch.proj252.dto.stopwatch.StopwatchPauseDto
import com.proj252.AIstopwatch.proj252.dto.stopwatch.StopwatchRunDto
import com.proj252.AIstopwatch.proj252.dto.stopwatch.StopwatchSyncDto
import jakarta.servlet.http.Cookie
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import java.util.Date
import java.util.HashMap

@WebMvcTest
class StopwatchControllerTest {

    @Autowired
    lateinit var mvc: MockMvc
    @Autowired
    lateinit var mapper: ObjectMapper

    val cookie: Cookie = Cookie("userId", "26")

    @Test
    fun runStopwatch() {

        val content: String = mapper.writeValueAsString(StopwatchRunDto(Date()))

        mvc.perform(post("/stopwatch/control/run")
            .content(content)
            .contentType(MediaType.APPLICATION_JSON)
            .cookie(cookie)
        )
            .andExpect(status().isOk)
    }

    @Test
    fun pauseStopwatch() {

        val content: String = mapper.writeValueAsString(StopwatchPauseDto(Date()))

        mvc.perform(post("/stopwatch/control/pause")
            .content(content)
            .contentType(MediaType.APPLICATION_JSON)
            .cookie(cookie)
        )
            .andExpect(status().isOk)
    }

    @Test
    fun syncStopwatch() {
        val content: String = mapper.writeValueAsString(StopwatchSyncDto(353))

        mvc.perform(post("/stopwatch/sync")
            .content(content)
            .contentType(MediaType.APPLICATION_JSON)
            .cookie(cookie)
        )
            .andExpect(status().isOk)
    }

    @Test
    fun getTotalTime() {
        mvc.perform(get("/stopwatch/total")
            .contentType(MediaType.APPLICATION_JSON)
            .cookie(Cookie("userId", "2")))
            .andExpect(status().isOk)
            .andExpect(content().string("20"))
    }
}