package com.proj252.AIstopwatch.proj252.repository

import com.proj252.AIstopwatch.proj252.domain.CustomUser
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.*

@Repository
interface SdjUserRepo: JpaRepository<CustomUser,Long> {
    @Override
    override fun findById(id: Long): Optional<CustomUser>

}