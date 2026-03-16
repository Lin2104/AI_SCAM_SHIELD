package com.prototype.scam

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import java.net.URLEncoder
import java.util.concurrent.TimeUnit

object ScamTranslator {

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    private fun getLanguageCode(language: String): String {
        return when (language) {
            "Thai" -> "th"
            "Burmese" -> "my"
            "Vietnamese" -> "vi"
            "Indonesian" -> "id"
            "Malay" -> "ms"
            "Khmer" -> "km"
            "Lao" -> "lo"
            "Tagalog" -> "tl"
            "Chinese" -> "zh-CN"
            "Japanese" -> "ja"
            else -> "en"
        }
    }

    private val dictionary = mapOf(
        "phishing" to mapOf("th" to "ลิงก์หลอกลวง (Phishing)", "my" to "လိမ်လည်လှည့်ဖြားသော လင့်ခ်"),
        "fake admin" to mapOf("th" to "แอดมินปลอม", "my" to "အက်ဒမင်အတု"),
        "fraud" to mapOf("th" to "လိမ်လည်မှု", "my" to "လိမ်လည်မှု"),
        "scam" to mapOf("th" to "หลอกလวง", "my" to "လိမ်လည်ခြင်း"),
        "winner" to mapOf("th" to "หลอกลวงรับรางวัล", "my" to "ဆုမဲရရှိသည်ဟု လိမ်လည်ခြင်း"),
        "bank" to mapOf("th" to "การฉ้อโกงธนาคาร", "my" to "ဘဏ်လိမ်လည်မှု"),
        "impersonation" to mapOf("th" to "การแอบอ้างบุคคล", "my" to "ဟန်ဆောင်လိမ်လည်ခြင်း"),
        "malicious" to mapOf("th" to "ลิงก์อันตราย", "my" to "အန္တရာယ်ရှိသောလင့်ခ်"),
        "gambling" to mapOf("th" to "การพนัน", "my" to "လောင်းကစား")
    )

    suspend fun translate(text: String, targetLanguage: String): String = withContext(Dispatchers.IO) {
        val targetCode = getLanguageCode(targetLanguage)
        if (targetCode == "en" || text.isBlank()) return@withContext text

        val cleanInput = text.trim().lowercase()
        
        // 1. DICTIONARY MATCH (Only for short strings like titles/types)
        if (text.length < 40) {
            for ((key, translations) in dictionary) {
                if (cleanInput.contains(key)) {
                    translations[targetCode]?.let {
                        Log.d("ScamGuardAI", "Dictionary Match: $text -> $it")
                        return@withContext it
                    }
                }
            }
        }

        // 2. ONLINE TRANSLATION (For explanations)
        return@withContext try {
            val encodedText = URLEncoder.encode(text, "UTF-8")
            val url = "https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=$targetCode&dt=t&q=$encodedText"

            val request = Request.Builder()
                .url(url)
                // Use a standard Android browser User-Agent
                .header("User-Agent", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36")
                .build()
                
            val response = httpClient.newCall(request).execute()
            val body = response.body?.string()

            if (response.isSuccessful && body != null) {
                val jsonArray = JSONArray(body)
                val sentences = jsonArray.optJSONArray(0)
                if (sentences != null) {
                    val result = StringBuilder()
                    for (i in 0 until sentences.length()) {
                        val sentence = sentences.optJSONArray(i)
                        if (sentence != null && !sentence.isNull(0)) {
                            result.append(sentence.getString(0))
                        }
                    }
                    val translated = result.toString()
                    if (translated.isNotBlank() && translated.trim() != text.trim()) {
                        Log.d("ScamGuardAI", "Online Translation Success for Explanation")
                        return@withContext translated
                    }
                }
            }
            
            // EMERGENCY FALLBACK for Phishing
            if (cleanInput.contains("phishing")) {
                 return@withContext if (targetCode == "my") "လိမ်လည်လှည့်ဖြားသော လင့်ခ်" else "ลิงก์หลอกลวง"
            }
            
            Log.w("ScamGuardAI", "Translation failed, returned original English.")
            text 
        } catch (e: Exception) {
            Log.e("ScamGuardAI", "Translator error: ${e.message}")
            text
        }
    }
}
