package com.prototype.scam

import android.app.PendingIntent
import android.app.RemoteInput
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.core.app.NotificationManagerCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class NotificationActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        val sender = intent.getStringExtra("sender") ?: ""
        val body = intent.getStringExtra("body") ?: ""
        val notificationId = intent.getIntExtra("notification_id", 0)
        val externalId = if (intent.hasExtra("external_id")) intent.getLongExtra("external_id", -1L) else null

        // 1. Reset the duplication cache so the message can be detected again if sent later
        ScamNotificationListener.clearCache()

        // Dismiss the alert/assistant notification
        NotificationManagerCompat.from(context).cancel(notificationId)

        val database = ScamDatabase.getDatabase(context)
        val scope = CoroutineScope(Dispatchers.IO)

        when (action) {
            "ACTION_ALLOW" -> {
                Log.d("ScamGuard", "User allowed/restored message from $sender")
                scope.launch {
                    ScamUtils.restoreToInbox(context, sender, body)
                    val messages = database.scamDao().getAllMessagesSync()
                    val msgToDelete = messages.find { it.sender == sender && it.body == body }
                    msgToDelete?.let { database.scamDao().deleteMessage(it) }
                }
                Toast.makeText(context, "Message allowed and restored.", Toast.LENGTH_SHORT).show()
            }
            "ACTION_DELETE" -> {
                Log.d("ScamGuard", "User deleted threat from $sender")
                scope.launch {
                    val messages = database.scamDao().getAllMessagesSync()
                    val msgToDelete = messages.find { it.sender == sender && it.body == body }
                    msgToDelete?.let { database.scamDao().deleteMessage(it) }
                    ScamUtils.deleteFromSystemInbox(context, sender, body, externalId)
                }
                Toast.makeText(context, "Threat deleted permanently.", Toast.LENGTH_SHORT).show()
            }
            "ACTION_SEND_AI_REPLY" -> {
                val replyIntent = intent.getParcelableExtra<PendingIntent>("reply_intent")
                val remoteInputKey = intent.getStringExtra("remote_input_key")
                val replyText = intent.getStringExtra("reply_text")

                if (replyIntent != null && remoteInputKey != null && replyText != null) {
                    val remoteInputBundle = Bundle().apply { putCharSequence(remoteInputKey, replyText) }
                    val resultIntent = Intent()
                    RemoteInput.addResultsToIntent(
                        arrayOf(RemoteInput.Builder(remoteInputKey).build()), 
                        resultIntent, 
                        remoteInputBundle
                    )
                    
                    try {
                        replyIntent.send(context, 0, resultIntent)
                        Toast.makeText(context, "AI Assistant Replied: $replyText", Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Log.e("ScamGuard", "AI Assistant Reply failed: ${e.message}")
                    }
                }
            }
        }
    }
}
