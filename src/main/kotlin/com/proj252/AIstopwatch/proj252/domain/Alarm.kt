package com.proj252.AIstopwatch.proj252.domain

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import lombok.Data
import lombok.Getter
import lombok.NoArgsConstructor
import lombok.NonNull
import lombok.RequiredArgsConstructor
import lombok.Setter

@Entity
@Data //id setter는 막아야함
class Alarm {

    @Id
    private var ringtoneName: String = "default"

    @Column
    private var ison: Boolean = false

    @Column @NonNull
    private var userId: Long = -1
    //userId == -1일 때 초기화 오류


}