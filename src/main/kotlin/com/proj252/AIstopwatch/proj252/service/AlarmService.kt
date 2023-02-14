package com.proj252.AIstopwatch.proj252.service

import com.proj252.AIstopwatch.proj252.domain.Alarm
import com.proj252.AIstopwatch.proj252.domain.TmpReport
import com.proj252.AIstopwatch.proj252.dto.stopwatch.AlarmDto
import com.proj252.AIstopwatch.proj252.repository.SdjAlarmRepo
import com.proj252.AIstopwatch.proj252.repository.SdjTmpReportRepo
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import java.util.*

@Service
class AlarmService {

    private lateinit var alarmRepo: SdjAlarmRepo

    @Autowired
    //여기서 repo 갈아끼울 수 있음
    constructor(alarmRepo: SdjAlarmRepo){
        this.alarmRepo = alarmRepo
    }

    public fun setAlarm(userId:Long, ison: Int, ringtone: String){
        try {
            var alarm: Alarm? = alarmRepo.findById(userId).orElse(null)

            if(alarm == null){
                //exception
            }else{
                alarm.ison = ison
                alarm.ringtoneName = ringtone
                alarmRepo.save(alarm)
            }
        }catch (e: Exception){
            //!! 알아서 처리
            print("stopwatch save err, retry?")
        }
    }

    public fun getAlarm(userId: Long): AlarmDto?{
        var alarmDto: AlarmDto? = null
        try {
            val alarm: Alarm? = alarmRepo.findById(userId).orElse(null)

            if(alarm == null){
                //exception
            }else{
                alarmDto = AlarmDto(alarm.ison, alarm.ringtoneName)
            }

        }catch (e: Exception){
            //!! 알아서 처리
            print("stopwatch save err, retry?")
        }
        return alarmDto
    }
}