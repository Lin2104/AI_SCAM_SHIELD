package com.prototype.scam

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object VirusTotalAnalyzer {
    private const val VT_API_KEY = "43e17dff0e161c451f6bafc4d680005e72bf07b957752f321d5af40812e85820" // User should provide this
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    suspend fun analyzeUrl(url: String): VTResult = withContext(Dispatchers.IO) {
        if (VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY") return@withContext VTResult(false, "API Key missing")
        
        return@withContext try {
            val urlId = android.util.Base64.encodeToString(url.toByteArray(), android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE).trimEnd('=')
            val request = Request.Builder()
                .url("https://www.virustotal.com/api/v3/urls/$urlId")
                .addHeader("x-apikey", VT_API_KEY)
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val json = JSONObject(response.body?.string() ?: "")
                val stats = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats")
                val malicious = stats.getInt("malicious")
                val suspicious = stats.getInt("suspicious")
                
                if (malicious > 0 || suspicious > 1) {
                    VTResult(true, "VirusTotal flagged this as malicious ($malicious detections)")
                } else {
                    VTResult(false, "Clean")
                }
            } else {
                VTResult(false, "VT lookup failed: ${response.code}")
            }
        } catch (e: Exception) {
            VTResult(false, "VT error: ${e.message}")
        }
    }

    data class VTResult(val isMalicious: Boolean, val reason: String)
}
