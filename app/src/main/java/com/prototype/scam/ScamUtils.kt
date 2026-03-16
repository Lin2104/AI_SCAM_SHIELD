package com.prototype.scam

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ContentUris
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.net.Uri
import android.os.Build
import android.provider.ContactsContract
import android.provider.Telephony
import android.telephony.TelephonyManager
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

object ScamUtils {
    const val CHANNEL_ID = "scam_alerts"
    
    private const val DEFAULT_BOT_TOKEN = "8684181969:AAGMjSktexdlQmSKsQMuYRo7adSQ7EhLwpo" 

    fun getPreferredLanguage(context: Context): String {
        val prefs = context.getSharedPreferences("scam_prefs", Context.MODE_PRIVATE)
        return prefs.getString("user_language", "English") ?: "English"
    }

    fun getBotConfig(context: Context): Pair<String, String?> {
        val prefs = context.getSharedPreferences("scam_prefs", Context.MODE_PRIVATE)
        val token = prefs.getString("bot_token", "") ?: ""
        val finalToken = if (token.isNotEmpty()) token else DEFAULT_BOT_TOKEN
        val chatId = prefs.getString("chat_id", null)
        return Pair(finalToken, chatId)
    }

    fun isContact(context: Context, senderName: String): Boolean {
        if (senderName.isBlank() || senderName == "Unknown") return false
        return try {
            val uri = Uri.withAppendedPath(ContactsContract.Contacts.CONTENT_FILTER_URI, Uri.encode(senderName))
            val cursor: Cursor? = context.contentResolver.query(uri, arrayOf(ContactsContract.Contacts.DISPLAY_NAME), null, null, null)
            cursor?.use { it.count > 0 } ?: false
        } catch (e: Exception) { false }
    }

    fun getRegionalBrands(context: Context): List<String> {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        val countryCode = tm.networkCountryIso.lowercase()
        
        return when (countryCode) {
            "mm" -> listOf("KBZ Pay", "WaveMoney", "AYA Bank", "CB Pay", "Mytel Pay")
            "th" -> listOf("K-Bank", "SCB", "PromptPay", "TrueMoney", "ThaiPost")
            "id" -> listOf("GoPay", "OVO", "Dana", "BCA", "Mandiri", "KTP Digital")
            "vn" -> listOf("MoMo", "ZaloPay", "ViettelPay", "Vietcombank")
            "my" -> listOf("Maybank", "Touch 'n Go", "GrabPay", "CIMB")
            "ph" -> listOf("GCash", "Maya", "BPI", "BDO")
            else -> listOf("Shopee", "Lazada", "TikTok", "Bank", "Admin")
        }
    }

    // --- RE-ADDED LOCALIZATION HELPERS FOR SMS ---
    fun getLocalizedKnownThreatReason(context: Context): String {
        return when (getPreferredLanguage(context)) {
            "Burmese" -> "[Known Threat] ဒေတာဘေ့စ်တွင် သိရှိပြီးသား အန္တရာယ်ရှိသောလင့်ခ်တစ်ခုကို တွေ့ရှိရပါသည်။"
            "Thai" -> "[Known Threat] พบลิงก์ที่เป็นอันตรายในฐานข้อมูล"
            else -> "[Known Threat] Malicious link found in database."
        }
    }

    fun getLocalizedKnownThreatExplanation(context: Context, type: String): String {
        return when (getPreferredLanguage(context)) {
            "Burmese" -> "ဤလင့်ခ်ကို ယခင်က $type အဖြစ် အန္တရာယ်ရှိကြောင်း သတ်မှတ်ထားပါသည်။"
            "Thai" -> "ลิงก์นี้เคยถูกทำเครื่องหมายว่าเป็น $type ซึ่งเป็นอันตราย"
            else -> "This link was previously flagged as $type."
        }
    }

    fun getLocalizedVirusTotalReason(context: Context): String {
        return when (getPreferredLanguage(context)) {
            "Burmese" -> "[VirusTotal] ကမ္ဘာလုံးဆိုင်ရာ လုံခြုံရေးအင်ဂျင်များမှ အန္တရာယ်ရှိကြောင်း သတ်မှတ်လိုက်သည်။"
            "Thai" -> "[VirusTotal] ตรวจพบอันตรายโดยระบบความปลอดภัยระดับโลก"
            else -> "[VirusTotal] Flagged by global security engines."
        }
    }

    fun getLocalizedVirusTotalExplanation(context: Context, details: String): String {
        return when (getPreferredLanguage(context)) {
            "Burmese" -> "VirusTotal မှ အသေးစိတ်တွေ့ရှိချက်များ: $details"
            "Thai" -> "รายละเอียดจาก VirusTotal: $details"
            else -> "Details from VirusTotal: $details"
        }
    }

    fun showThreatNotification(context: Context, sender: String, body: String) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        createChannels(context, notificationManager)

        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_IMMUTABLE)

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("🚨 Threat Blocked")
            .setContentText("From: $sender")
            .setStyle(NotificationCompat.BigTextStyle().bigText("Scam detected: $body"))
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .build()

        notificationManager.notify((sender + body).hashCode(), notification)
        relayToTelegramBot(context, "🚨 *SCAM DETECTED* 🚨\n\nSource: $sender\nAnalysis: $body\n\nStay safe!")
    }

    private fun relayToTelegramBot(context: Context, message: String) {
        val (token, chatId) = getBotConfig(context)
        if (chatId.isNullOrEmpty()) return

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val encodedMsg = URLEncoder.encode(message, "UTF-8")
                val urlString = "https://api.telegram.org/bot$token/sendMessage?chat_id=$chatId&text=$encodedMsg"
                val conn = URL(urlString).openConnection() as HttpURLConnection
                conn.requestMethod = "GET"
                if (conn.responseCode == 200) Log.i("ScamGuardBot", "Relay Success")
            } catch (e: Exception) {
                Log.e("ScamGuardBot", "Relay failed: ${e.message}")
            }
        }
    }

    suspend fun resolveShortenedUrl(shortUrl: String): String {
        return try {
            val url = URL(shortUrl)
            val connection = url.openConnection() as HttpURLConnection
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 5000
            connection.readTimeout = 5000
            connection.connect()
            val expandedUrl = connection.getHeaderField("Location")
            connection.disconnect()
            expandedUrl ?: shortUrl
        } catch (e: Exception) { shortUrl }
    }

    fun deleteFromSystemInbox(context: Context, sender: String, body: String, externalId: Long?) {
        try {
            if (externalId != null && externalId != -1L) {
                val uri = ContentUris.withAppendedId(Telephony.Sms.CONTENT_URI, externalId)
                context.contentResolver.delete(uri, null, null)
            }
        } catch (e: Exception) { }
    }

    fun restoreToInbox(context: Context, sender: String, body: String) {
        try {
            val values = ContentValues().apply {
                put(Telephony.Sms.ADDRESS, sender.substringBefore(" ("))
                put(Telephony.Sms.BODY, body)
                put(Telephony.Sms.TYPE, Telephony.Sms.MESSAGE_TYPE_INBOX)
            }
            context.contentResolver.insert(Telephony.Sms.Inbox.CONTENT_URI, values)
        } catch (e: Exception) { }
    }

    private fun createChannels(context: Context, manager: NotificationManager) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val threatChannel = NotificationChannel(CHANNEL_ID, "Threats", NotificationManager.IMPORTANCE_HIGH).apply {
                enableLights(true)
                enableVibration(true)
            }
            manager.createNotificationChannel(threatChannel)
        }
    }
}
