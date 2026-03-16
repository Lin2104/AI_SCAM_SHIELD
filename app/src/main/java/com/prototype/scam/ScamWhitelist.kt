package com.prototype.scam

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scam_whitelist")
data class ScamWhitelist(
    @PrimaryKey val sender: String,
    val timestamp: Long = System.currentTimeMillis()
)
