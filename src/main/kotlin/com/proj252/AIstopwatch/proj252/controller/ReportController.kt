package com.proj252.AIstopwatch.proj252.controller

import com.proj252.AIstopwatch.proj252.domain.Report
import com.proj252.AIstopwatch.proj252.service.getDate
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.bind.annotation.CookieValue
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

import java.util.HashMap

//@RestController
//@RequestMapping("/daily-report")
//class ReportController {
//    private final var reportService: ReportService
//
//    @Autowired
//    constructor(reportService: ReportService){
//        this.reportService = reportService
//    }
//
//    @GetMapping
//    fun getReport(@RequestParam date: String, @CookieValue userId: Long): Report {
//        var map: HashMap<String, Any> = HashMap<String, Any>()
//        val dateTime: String = getDate().format(date)
//
//        return reportService.showReport(userId = userId, date = dateTime)
//    }
//
//
//}