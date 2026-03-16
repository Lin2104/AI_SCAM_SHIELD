package com.prototype.scam

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ScamDao {
    @Query("SELECT * FROM scam_messages ORDER BY timestamp DESC")
    fun getAllMessages(): Flow<List<ScamMessage>>

    @Query("SELECT * FROM scam_messages")
    suspend fun getAllMessagesSync(): List<ScamMessage>

    @Query("SELECT * FROM scam_messages WHERE sender LIKE :senderPattern ORDER BY timestamp DESC LIMIT 5")
    suspend fun getHistoryBySender(senderPattern: String): List<ScamMessage>

    @Insert
    suspend fun insertMessage(message: ScamMessage)

    @Delete
    suspend fun deleteMessage(message: ScamMessage)

    // --- WHITELIST FUNCTIONS ---
    @Query("SELECT EXISTS(SELECT 1 FROM scam_whitelist WHERE sender = :sender)")
    suspend fun isWhitelisted(sender: String): Boolean

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun addToWhitelist(entry: ScamWhitelist)

    @Query("DELETE FROM scam_whitelist WHERE sender = :sender")
    suspend fun removeFromWhitelist(sender: String)
}