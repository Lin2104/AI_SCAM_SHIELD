package com.prototype.scam

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import kotlinx.coroutines.*

class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION &&
            intent.action != Telephony.Sms.Intents.SMS_DELIVER_ACTION) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        val sender = messages[0].displayOriginatingAddress ?: "Unknown"
        val rawMessageBody = messages.joinToString(separator = "") { it.displayMessageBody ?: "" }

        if (rawMessageBody.isEmpty()) return

        val pendingResult = goAsync()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        scope.launch {
            try {
                Log.d("ScamGuardSms", "SMS Detection started for: $sender")
                
                val db = ScamDatabase.getDatabase(context)
                val isContact = ScamUtils.isContact(context, sender)
                val urls = GemmaAnalyzer.extractUrls(rawMessageBody)
                
                val highRiskKeywords = listOf("OTP", "verify", "password", "login", "winner", "prize", "money", "transfer", "urgent", "bank", "help", "borrow")
                val hasHighRisk = highRiskKeywords.any { rawMessageBody.contains(it, ignoreCase = true) }

                // 1. WHITE LIST CHECK (Explicitly allowed by user)
                if (db.scamDao().isWhitelisted(sender)) {
                    Log.d("ScamGuardSms", "Sender $sender is manually whitelisted. Skipping.")
                    return@launch
                }

                // 2. SMART CONTACT FILTERING
                // If it's a contact, skip ONLY if there are no URLs and no high-risk keywords.
                // This protects against hacked accounts sending malicious links.
                if (isContact && urls.isEmpty() && !hasHighRisk) {
                    Log.d("ScamGuardSms", "Contact $sender sent a safe-looking message. Skipping AI.")
                    return@launch
                }
                
                // 3. INSTANT LOCAL CHECK (Known Threat Database)
                if (urls.isNotEmpty()) {
                    for (url in urls) {
                        val resolved = ScamUtils.resolveShortenedUrl(url)
                        val existing = db.threatDao().getThreatById(resolved)
                        if (existing != null) {
                            quarantineSms(context, sender, ScamUtils.getLocalizedKnownThreatReason(context), rawMessageBody, ScamUtils.getLocalizedKnownThreatExplanation(context, existing.type))
                            return@launch
                        }
                    }
                }

                // 4. AI ANALYSIS
                withTimeout(30000) {
                    val aiResult = GemmaAnalyzer.analyzeMessage(context, sender, rawMessageBody, isContact = isContact)
                    if (aiResult.isScam) {
                        quarantineSms(context, sender, aiResult.reason, rawMessageBody, aiResult.explanation)
                    }
                }

            } catch (e: Exception) {
                Log.e("ScamGuardSms", "SMS Analysis Error: ${e.message}")
            } finally {
                pendingResult.finish()
            }
        }
    }
    
    private suspend fun quarantineSms(context: Context, sender: String, reason: String, fullContent: String, explanation: String) {
        val db = ScamDatabase.getDatabase(context)
        db.scamDao().insertMessage(ScamMessage(
            sender = "$sender (SMS)",
            body = reason,
            fullContent = fullContent,
            explanation = explanation,
            packageName = "com.android.mms"
        ))
        ScamUtils.showThreatNotification(context, "$sender (SMS)", reason)
    }
}
