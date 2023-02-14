package com.proj252.AIstopwatch.proj252.repository

import com.proj252.AIstopwatch.proj252.domain.User
import org.springframework.data.jpa.repository.JpaRepository
import java.util.*

interface SdjUserRepo: JpaRepository<User,Long> {
    @Override
    override fun findById(id: Long): Optional<User>

}