package com.proj252.AIstopwatch.proj252.service

import com.proj252.AIstopwatch.proj252.domain.TmpChangeTime
import com.proj252.AIstopwatch.proj252.domain.TmpReport
import com.proj252.AIstopwatch.proj252.domain.TmpWarnTime
import com.proj252.AIstopwatch.proj252.repository.SdjTmpReportRepo
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.*

@Service
@Transactional
//!! Service니까 날짜 변화시 초기화 등이 여기서 반영되어야 한다는 것. 각자마다 조회 & 날짜 변경 확인 & 이후 진행하는 로직을 만들 것.
class StopwatchService {
    private lateinit var tmpReportRepo: SdjTmpReportRepo

    @Autowired
    //여기서 repo 갈아끼울 수 있음
    constructor(tmpReportRepo: SdjTmpReportRepo){
        this.tmpReportRepo = tmpReportRepo
    }

    public fun getTotalTime(userId: Long, date: Date): Int{
        var totalTime: Int = 0
        try {
            val report: TmpReport? =
                tmpReportRepo.findTmpReportByUser_UserIdAndDate(userId, date).orElse(null)
            if(report != null){
                totalTime = report.totalTime
            }else{
                totalTime = -1
            }

        }catch (e: Exception){
            print("stopwatch get time err, retry?")
            totalTime = -1
        }
        return totalTime
    }
    public fun runStopwatch(userId: Long, date: Date) {
        try {
            var report: TmpReport? =
                tmpReportRepo.findTmpReportByUser_UserIdAndDate(userId, date).orElse(null)
            if(report != null){
                val changeTime: TmpChangeTime = TmpChangeTime(date,report)
                report.changeTimes.add(changeTime)
                tmpReportRepo.save(report)
            }else{
                print("NO Reports!")
            }

        } catch (e: Exception) {
            //!! 알아서 처리
            print("stopwatch run err, retry?")
        }
    }
    public fun pauseStopwatch(userId: Long, date: Date){
        try{
            var report: TmpReport? =
                tmpReportRepo.findTmpReportByUser_UserIdAndDate(userId, date).orElse(null)
            if(report != null){
                val changeTime: TmpChangeTime = TmpChangeTime(date,report)
                report.changeTimes.add(changeTime)
                tmpReportRepo.save(report)
            }else{
                //make exception
            }

        }catch (e: Exception){
            //!! 알아서 처리
            print("stopwatch pause err, retry?")
        }
    }

    public fun warnStopwatch(userId: Long, date: Date){
        try{
            var report: TmpReport? =
                tmpReportRepo.findTmpReportByUser_UserIdAndDate(userId, date).orElse(null)
            if(report != null){
                val warnTime: TmpWarnTime = TmpWarnTime(date,report)
                report.warnTimes.add(warnTime)
                tmpReportRepo.save(report)
            }else{
                //make exception
            }
        }catch (e: Exception){
            //!! 알아서 처리
            print("stopwatch warn err, retry?")
        }
    }
    public fun saveStopwatch(userId: Long, date: Date, time: Int){
        try {
            var report: TmpReport? =
                tmpReportRepo.findTmpReportByUser_UserIdAndDate(userId, date).orElse(null)
            if(report != null){
                report.totalTime = time
                tmpReportRepo.save(report)
            }else{
                print("DB에서 Report를 찾을 수 없습니다.")
            }
        }catch (e: Exception){
            //!! 알아서 처리
            print("stopwatch save err, retry?")
        }
    }

}