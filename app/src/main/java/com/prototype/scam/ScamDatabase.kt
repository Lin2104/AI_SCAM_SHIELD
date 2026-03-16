package com.prototype.scam

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(entities = [ScamMessage::class, ScamThreat::class, ScamWhitelist::class], version = 9, exportSchema = false)
abstract class ScamDatabase : RoomDatabase() {
    abstract fun scamDao(): ScamDao
    abstract fun threatDao(): ScamThreatDao

    companion object {
        @Volatile
        private var INSTANCE: ScamDatabase? = null

        fun getDatabase(context: Context): ScamDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    ScamDatabase::class.java,
                    "scam_database"
                )
                .fallbackToDestructiveMigration()
                .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
