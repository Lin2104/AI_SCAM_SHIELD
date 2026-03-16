package com.prototype.scam

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.database.Cursor
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import kotlinx.coroutines.*
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

class ScamNotificationListener : NotificationListenerService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    
    companion object {
        private val processedMessages = Collections.synchronizedSet(mutableSetOf<Int>())
        val intentCache = ConcurrentHashMap<Int, PendingIntent>()

        fun clearCache() { 
            processedMessages.clear()
            intentCache.clear()
        }
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        Log.i("ScamGuard", "Notification Shield Service Connected and Active.")
    }

    private fun extractBitmap(context: Context, extras: Bundle): Bitmap? {
        var bitmap: Bitmap? = null
        try {
            bitmap = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                extras.getParcelable(Notification.EXTRA_PICTURE, Bitmap::class.java) ?:
                extras.getParcelable(Notification.EXTRA_LARGE_ICON, Bitmap::class.java)
            } else {
                @Suppress("DEPRECATION")
                (extras.getParcelable(Notification.EXTRA_PICTURE) as? Bitmap) ?:
                @Suppress("DEPRECATION")
                (extras.getParcelable(Notification.EXTRA_LARGE_ICON) as? Bitmap)
            }
        } catch (e: Exception) {
            Log.e("ScamGuard", "Image load error: ${e.message}")
        }
        return bitmap
    }
    
    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val packageName = sbn.packageName
        
        val systemKeywords = listOf(
            "android", "systemui", "settings", "gms", "vending", "telephony",
            "overlay", "launcher", "intelligence", "wellbeing", "securitylog", 
            "knox", "galaxy", "miui", "hms", "huawei", "oppo", "vivo"
        )
        if (packageName == this.packageName || systemKeywords.any { packageName.contains(it, ignoreCase = true) }) {
            return
        }

        val extras = sbn.notification.extras
        var sender = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: "Unknown"
        val conversationTitle = extras.getCharSequence(Notification.EXTRA_CONVERSATION_TITLE)?.toString()
        
        if (conversationTitle != null && sender == conversationTitle) {
            val messages = extras.getParcelableArray(Notification.EXTRA_MESSAGES)
            if (messages != null && messages.isNotEmpty()) {
                val lastMsg = messages.last() as? Bundle
                val person = lastMsg?.getCharSequence("sender")?.toString()
                if (person != null) sender = "$person ($conversationTitle)"
            }
        }

        val rawText = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        if (sender.contains("ScamGuard", ignoreCase = true) || rawText.contains("🛡️")) return
        
        scope.launch {
            val finalMessage = rawText.trim()
            if (finalMessage.isEmpty()) return@launch

            val db = ScamDatabase.getDatabase(applicationContext)
            val isContact = ScamUtils.isContact(applicationContext, sender)

            // 1. WHITE LIST CHECK
            if (db.scamDao().isWhitelisted(sender)) {
                return@launch
            }

            val urls = GemmaAnalyzer.extractUrls(finalMessage)
            val highRiskKeywords = listOf("OTP", "verify", "password", "login", "winner", "prize", "gift card", "bank account", "suspended", "urgent action", "verify your account", "money", "transfer", "help", "borrow")
            val hasHighRisk = highRiskKeywords.any { finalMessage.contains(it, ignoreCase = true) }
            val screenshot = extractBitmap(applicationContext, extras)
            
            // SMART FILTERING:
            // If it's a contact, skip ONLY if there are no URLs, no high-risk keywords, and no QR codes.
            if (isContact && urls.isEmpty() && !hasHighRisk && screenshot == null) {
                return@launch
            }

            // For unknown senders, we are still fairly strict but slightly more relaxed for short messages
            if (!isContact && urls.isEmpty() && !hasHighRisk && screenshot == null && finalMessage.length < 30) {
                return@launch
            }

            val contentHash = (sender + finalMessage + (screenshot?.hashCode() ?: 0)).hashCode()
            if (processedMessages.contains(contentHash)) return@launch
            processedMessages.add(contentHash)
            
            sbn.notification.contentIntent?.let { intentCache[contentHash] = it }
            val shortcutId = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                try { sbn.notification.shortcutId } catch (e: Exception) { null }
            } else null

            try {
                val appName = try { 
                    packageManager.getApplicationLabel(packageManager.getApplicationInfo(packageName, 0)).toString() 
                } catch (e: Exception) { packageName }

                withTimeout(45000) { 
                    val aiResult = GemmaAnalyzer.analyzeMessage(applicationContext, sender, finalMessage, screenshot, isContact = isContact)
                    
                    // Use a very high threshold for contacts (0.85) and high for others (0.75)
                    val requiredConfidence = if (isContact) 0.85f else 0.75f
                    if (aiResult.isScam && aiResult.confidence >= requiredConfidence) {
                        quarantineMessage(sbn, sender, appName, aiResult.reason, finalMessage, aiResult.explanation, packageName, shortcutId, contentHash, aiResult.isQrCode, aiResult.websitePreview)
                    }
                }
            } catch (e: Exception) {
                Log.e("ScamGuard", "Detection error for $sender: ${e.message}")
            }
        }
    }

    private suspend fun quarantineMessage(sbn: StatusBarNotification, sender: String, appName: String, reason: String, fullContent: String, explanation: String, packageName: String, shortcutId: String?, hash: Int, isQr: Boolean, preview: String?) {
        cancelNotification(sbn.key)
        val db = ScamDatabase.getDatabase(applicationContext)
        db.scamDao().insertMessage(ScamMessage(
            sender = "$sender [$appName]", // Platform is now clearly visible in the title
            body = reason,
            fullContent = fullContent,
            explanation = explanation,
            packageName = packageName,
            shortcutId = shortcutId,
            externalId = hash.toLong(),
            isQrCode = isQr,
            websitePreview = preview
        ))
        ScamUtils.showThreatNotification(applicationContext, "$sender [$appName]", reason)
    }
}
