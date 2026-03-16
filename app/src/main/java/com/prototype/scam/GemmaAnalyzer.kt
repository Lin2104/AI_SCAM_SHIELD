package com.prototype.scam

import android.content.Context
import android.graphics.Bitmap
import android.util.Log
import android.util.Patterns
import com.google.mediapipe.tasks.genai.llminference.LlmInference
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import org.jsoup.Jsoup
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.TimeUnit
import java.security.MessageDigest

object GemmaAnalyzer {
    private const val OLLAMA_BASE_URL = "http://192.168.123.2:11434"
    private const val OPENROUTER_API_KEY = "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"
    private const val MODEL_OLLAMA = "llama3" 
    private const val MODEL_FALLBACK = "meta-llama/llama-3.1-8b-instruct:free"
    
    private var llmInference: LlmInference? = null

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(60, TimeUnit.SECONDS) 
        .readTimeout(60, TimeUnit.SECONDS)
        .build()

    /**
     * Ensures the Gemma model exists in internal storage. 
     * If not, it copies it from the 'assets' folder.
     */
    private fun ensureModelExists(context: Context): File? {
        val modelFile = File(context.filesDir, "gemma.bin")
        if (modelFile.exists()) return modelFile

        return try {
            Log.i("ScamGuardAI", "First run: Copying AI model from assets...")
            context.assets.open("gemma.bin").use { inputStream ->
                FileOutputStream(modelFile).use { outputStream ->
                    inputStream.copyTo(outputStream)
                }
            }
            Log.i("ScamGuardAI", "Model copy successful!")
            modelFile
        } catch (e: Exception) {
            Log.e("ScamGuardAI", "Failed to copy model from assets: ${e.message}")
            null
        }
    }

    private fun initLocalLLM(context: Context) {
        if (llmInference != null) return
        try {
            val modelFile = ensureModelExists(context)
            if (modelFile != null && modelFile.exists()) {
                val options = LlmInference.LlmInferenceOptions.builder()
                    .setModelPath(modelFile.absolutePath)
                    .setMaxTokens(512)
                    .build()
                llmInference = LlmInference.createFromOptions(context, options)
                Log.i("ScamGuardAI", "On-Device LLM (Gemma) Ready")
            }
        } catch (e: Exception) {
            Log.e("ScamGuardAI", "Local LLM Init failed: ${e.message}")
        }
    }

    private suspend fun callLocalLLM(context: Context, prompt: String): String? = withContext(Dispatchers.IO) {
        initLocalLLM(context)
        return@withContext try {
            llmInference?.generateResponse(prompt)
        } catch (e: Exception) { 
            Log.e("ScamGuardAI", "Local Inference Error: ${e.message}")
            null 
        }
    }

    fun extractUrls(text: String): List<String> = mutableListOf<String>().apply {
        val matcher = Patterns.WEB_URL.matcher(text)
        while (matcher.find()) matcher.group()?.let { add(it) }
    }

    private fun getTargetLanguage(context: Context): String {
        val prefs = context.getSharedPreferences("scam_prefs", Context.MODE_PRIVATE)
        return prefs.getString("user_language", "English") ?: "English"
    }

    private suspend fun scanQrCodes(bitmap: Bitmap): List<String> {
        return try {
            val image = InputImage.fromBitmap(bitmap, 0)
            val barcodes = BarcodeScanning.getClient().process(image).await()
            barcodes.mapNotNull { it.rawValue }
        } catch (e: Exception) { emptyList() }
    }

    private suspend fun callOllama(prompt: String, isJson: Boolean = false): String? = withContext(Dispatchers.IO) {
        val generateUrl = "$OLLAMA_BASE_URL/api/generate"
        val jsonBody = JSONObject().apply {
            put("model", MODEL_OLLAMA)
            put("prompt", prompt)
            put("stream", false)
            if (isJson) put("format", "json") 
        }
        return@withContext try {
            val response = httpClient.newCall(Request.Builder().url(generateUrl).post(jsonBody.toString().toRequestBody("application/json".toMediaType())).build()).execute()
            if (response.isSuccessful) JSONObject(response.body?.string() ?: "").getString("response") else null
        } catch (e: Exception) { null }
    }

    suspend fun analyzeMessage(context: Context, sender: String, message: String, screenshot: Bitmap? = null, isContact: Boolean = false): AnalysisResult = withContext(Dispatchers.IO) {
        val userLang = getTargetLanguage(context)
        val qrUrls = screenshot?.let { scanQrCodes(it) } ?: emptyList()
        val combinedContent = if (qrUrls.isNotEmpty()) "$message [QR: ${qrUrls.joinToString()}]" else message

        val prompt = """
            You are a Cybersecurity Expert. Analyze the following message for scam or phishing attempts.
            ${if (isContact) "NOTE: The sender is in the user's CONTACT LIST. Only flag if it looks like the account was HACKED (e.g., suspicious links, unusual requests for money/help)." else ""}
            
            Be careful not to flag legitimate messages. Only flag as a scam if you are highly certain.
            
            Sender: "$sender"
            Content: "$combinedContent"
            
            Respond ONLY in JSON format:
            {
              "isScam": boolean,
              "confidence": float (0.0 to 1.0),
              "reason": "Short reason (e.g., Phishing, Fake Admin, Fraud)",
              "explanation": "Brief explanation of why it is or is not a scam"
            }
        """.trimIndent()

        // TIERED EXECUTION
        var aiResultText = callLocalLLM(context, prompt)
        var source = "On-Device AI"

        if (aiResultText == null) {
            aiResultText = callOllama(prompt, isJson = true)
            source = "Ollama (LAN)"
        }

        if (aiResultText == null) {
            aiResultText = tryOpenRouterChat(MODEL_FALLBACK, "Security Expert", prompt)
            source = "OpenRouter (Cloud)"
        }
        
        if (aiResultText == null) return@withContext AnalysisResult(false, 0f, "OFFLINE", "No connection.")

        val parsed = parseJsonResult(aiResultText)
        
        // Final sanity check: Increase threshold to reduce false positives
        // But if it's a contact, we require even higher confidence to avoid breaking friendship trust
        val threshold = if (isContact) 0.85f else 0.75f
        val finalIsScam = parsed.isScam && parsed.confidence >= threshold

        val finalReason = ScamTranslator.translate(parsed.reason, userLang)
        val finalExplanation = ScamTranslator.translate(parsed.explanation, userLang)

        return@withContext parsed.copy(isScam = finalIsScam, reason = finalReason, explanation = finalExplanation, source = source)
    }

    private fun parseJsonResult(jsonResponse: String): AnalysisResult {
        return try {
            val cleaned = jsonResponse.trim().substringAfter("{").substringBeforeLast("}")
            val fullJson = "{$cleaned}"
            val json = JSONObject(fullJson)
            AnalysisResult(
                json.optBoolean("isScam", false), 
                json.optDouble("confidence", 0.0).toFloat(), 
                json.optString("reason", "Analyzed"), 
                json.optString("explanation", "")
            )
        } catch (e: Exception) {
            // More conservative manual parsing
            val isScam = jsonResponse.contains("\"isScam\": true", ignoreCase = true)
            AnalysisResult(isScam, if (isScam) 0.6f else 0.0f, "Manual Parse", jsonResponse)
        }
    }

    suspend fun askMentor(context: Context, question: String, language: String): String? = withContext(Dispatchers.IO) {
        val prompt = "Cybersecurity Forensic Mentor. Answer in detail: $question"
        val result = callLocalLLM(context, prompt) ?: callOllama(prompt) ?: tryOpenRouterChat(MODEL_FALLBACK, "Expert", prompt)
        return@withContext if (result != null) ScamTranslator.translate(result, language) else "Offline."
    }

    private fun tryOpenRouterChat(model: String, system: String, user: String): String? {
        return try {
            val jsonBody = JSONObject().apply {
                put("model", model)
                put("messages", JSONArray().apply { 
                    put(JSONObject().apply { put("role", "system"); put("content", system) })
                    put(JSONObject().apply { put("role", "user"); put("content", user) }) 
                })
            }
            val response = httpClient.newCall(Request.Builder().url("https://openrouter.ai/api/v1/chat/completions").addHeader("Authorization", "Bearer $OPENROUTER_API_KEY").post(jsonBody.toString().toRequestBody("application/json".toMediaType())).build()).execute()
            if (response.isSuccessful) JSONObject(response.body?.string() ?: "").getJSONArray("choices").getJSONObject(0).getJSONObject("message").getString("content") else null
        } catch (e: Exception) { null }
    }

    data class AnalysisResult(val isScam: Boolean, val confidence: Float, val reason: String, val explanation: String, val isQrCode: Boolean = false, val websitePreview: String? = null, val source: String = "AI")
}
