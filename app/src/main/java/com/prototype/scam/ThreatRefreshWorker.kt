package com.prototype.scam

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.BufferedReader
import java.io.InputStreamReader

class ThreatRefreshWorker(appContext: Context, workerParams: WorkerParameters) :
    CoroutineWorker(appContext, workerParams) {

    private val client = OkHttpClient()
    
    private val GLOBAL_THREAT_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt"

    override suspend fun doWork(): Result {
        Log.i("ScamGuardWork", "Worker starting: Beginning daily threat synchronization.")
        val context = applicationContext
        val db = ScamDatabase.getDatabase(context)
        
        return try {
            // Fetch from the primary global threat source.
            val success = fetchThreats(db, GLOBAL_THREAT_URL, "Phishing.Database")
            
            if (!success) {
                Log.e("ScamGuardWork", "Global threat source failed. Verify GitHub connectivity.")
            }

            revalidateLocalUrls(db)
            Log.i("ScamGuardWork", "Worker finished: Threat synchronization complete.")
            Result.success()
        } catch (e: Exception) {
            Log.e("ScamGuardWork", "Worker failed critically during synchronization.", e)
            Result.retry()
        }
    }

    private suspend fun fetchThreats(db: ScamDatabase, url: String, sourceName: String): Boolean {
        try {
            Log.d("ScamGuardWork", "Attempting to fetch threats from: $url")
            val request = Request.Builder().url(url).addHeader("User-Agent", "Mozilla/5.0").build()
            
            val response = withContext(Dispatchers.IO) { client.newCall(request).execute() }
            
            if (response.isSuccessful) {
                response.body?.byteStream()?.use { stream ->
                    val reader = BufferedReader(InputStreamReader(stream))
                    val newThreats = mutableListOf<ScamThreat>()
                    
                    var line: String?
                    var count = 0
                    while (reader.readLine().also { line = it } != null && count < 5000) {
                        val trimmed = line!!.trim()
                        if (trimmed.isNotBlank() && !trimmed.startsWith("#")) {
                            newThreats.add(ScamThreat(id = trimmed, type = "PHISHING", riskLevel = "HIGH", source = sourceName))
                            count++
                        }
                    }
                    
                    if (newThreats.isNotEmpty()) {
                        db.threatDao().insertThreats(newThreats)
                        Log.i("ScamGuardWork", "Success: Injected $count threats from $sourceName.")
                        return true
                    }
                }
            } else {
                Log.w("ScamGuardWork", "Download failed for $url with code: ${response.code}")
            }
        } catch (e: Exception) {
            Log.e("ScamGuardWork", "Error syncing from $url", e)
        }
        return false
    }

    private suspend fun revalidateLocalUrls(db: ScamDatabase) {
        val messages = db.scamDao().getAllMessagesSync()
        if (messages.isEmpty()) return
        
        Log.d("ScamGuardWork", "Re-validating locally found URLs...")
        val urlsToRecheck = messages.flatMap { GemmaAnalyzer.extractUrls(it.fullContent) }.toSet()

        for (url in urlsToRecheck) {
            val vtResult = VirusTotalAnalyzer.analyzeUrl(url)
            if (vtResult.isMalicious) {
                db.threatDao().insertThreat(ScamThreat(id = url, type = "PHISHING", riskLevel = "CRITICAL", source = "VirusTotal (Re-check)"))
            }
        }
    }
}
