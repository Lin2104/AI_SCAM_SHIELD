package com.prototype.scam

import android.app.Application
import android.provider.Telephony
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch

class ScamViewModel(application: Application) : AndroidViewModel(application) {
    private val db = ScamDatabase.getDatabase(application)
    private val dao = db.scamDao()
    val allMessages: Flow<List<ScamMessage>> = dao.getAllMessages()

    fun deleteMessage(message: ScamMessage) {
        viewModelScope.launch {
            dao.deleteMessage(message)
        }
    }

    fun scanInbox() {
        viewModelScope.launch {
            val context = getApplication<Application>().applicationContext
            try {
                val cursor = context.contentResolver.query(
                    Telephony.Sms.Inbox.CONTENT_URI,
                    arrayOf(Telephony.Sms._ID, Telephony.Sms.ADDRESS, Telephony.Sms.BODY, Telephony.Sms.DATE),
                    null, null, "${Telephony.Sms.DATE} DESC"
                )

                cursor?.use {
                    val idIdx = it.getColumnIndex(Telephony.Sms._ID)
                    val addressIdx = it.getColumnIndex(Telephony.Sms.ADDRESS)
                    val bodyIdx = it.getColumnIndex(Telephony.Sms.BODY)
                    
                    if (idIdx == -1 || addressIdx == -1 || bodyIdx == -1) return@launch

                    var count = 0
                    while (it.moveToNext() && count < 20) {
                        val systemId = it.getLong(idIdx)
                        val sender = it.getString(addressIdx) ?: "Unknown"
                        val body = it.getString(bodyIdx) ?: ""
                        
                        // Check if we already analyzed this message to avoid duplicates
                        if (body.contains("bit.ly", ignoreCase = true) || 
                            body.contains("http", ignoreCase = true) ||
                            body.contains("winner", ignoreCase = true) ||
                            body.contains("bank", ignoreCase = true)) {
                            
                            val isContact = ScamUtils.isContact(context, sender)
                            // For inbox scan, we don't have a screenshot/bitmap, so we pass null
                            val aiResult = GemmaAnalyzer.analyzeMessage(context, sender, body, null, isContact = isContact)

                            if (aiResult.isScam) {
                                dao.insertMessage(ScamMessage(
                                    sender = "$sender (Inbox Scan)",
                                    body = "[AI: ${aiResult.reason}]",
                                    fullContent = body,
                                    explanation = aiResult.explanation,
                                    externalId = systemId
                                ))
                            }
                        }
                        count++
                    }
                }
            } catch (e: Exception) {
                Log.e("ScamViewModel", "Inbox scan failed: ${e.message}")
            }
        }
    }
}
