package com.prototype.scam

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ScamThreatDao {
    @Query("SELECT * FROM scam_threats")
    fun getAllThreats(): Flow<List<ScamThreat>>

    @Query("SELECT * FROM scam_threats WHERE id = :id LIMIT 1")
    suspend fun getThreatById(id: String): ScamThreat?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertThreat(threat: ScamThreat)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertThreats(threats: List<ScamThreat>)
}
