package com.prototype.scam

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scam_threats")
data class ScamThreat(
    @PrimaryKey val id: String, // This could be the URL or a hash of the content
    val type: String, // "URL", "PHISHING", "BANK", "SOCIAL_ENGINEERING", "QR"
    val riskLevel: String, // "HIGH", "CRITICAL"
    val source: String, // "VirusTotal", "AI_Manual", "Community"
    val timestamp: Long = System.currentTimeMillis()
)
