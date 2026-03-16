package com.prototype.scam

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scam_messages")
data class ScamMessage(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val sender: String,
    val body: String, 
    val fullContent: String = "", 
    val explanation: String = "",
    val packageName: String = "", 
    val shortcutId: String? = null,
    val isQrCode: Boolean = false, // Added for visual feedback
    val websitePreview: String? = null, // Added for Deep-Link Safe Preview
    val timestamp: Long = System.currentTimeMillis(),
    val externalId: Long? = null
)
