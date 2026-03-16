package com.prototype.scam

import android.Manifest
import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.work.*
import com.prototype.scam.ui.theme.SCAMTheme
import kotlinx.coroutines.launch
import java.util.concurrent.TimeUnit

class MainActivity : ComponentActivity() {

    private val requestRoleLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            Toast.makeText(this, "Real-time SMS Shield Active!", Toast.LENGTH_SHORT).show()
        }
    }

    private val permissionsToRequest = mutableListOf(
        Manifest.permission.RECEIVE_SMS,
        Manifest.permission.READ_SMS,
        Manifest.permission.SEND_SMS,
        Manifest.permission.READ_CONTACTS
    ).apply {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            add(Manifest.permission.POST_NOTIFICATIONS)
        }
    }.toTypedArray()

    private val requestPermissionsLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.entries.all { it.value }
        if (allGranted) {
            Toast.makeText(this, "Permissions Granted!", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        checkAndRequestPermissions()
        setupThreatDatabaseRefresh()

        handleIntent(intent)

        setContent {
            SCAMTheme {
                val viewModel: ScamViewModel = viewModel()
                val messages by viewModel.allMessages.collectAsState(initial = emptyList())
                val scope = rememberCoroutineScope()
                val db = ScamDatabase.getDatabase(this)
                
                var currentLanguage by remember { 
                    mutableStateOf(getSharedPreferences("scam_prefs", Context.MODE_PRIVATE)
                        .getString("user_language", "English") ?: "English") 
                }

                var mentorQuestion by remember { mutableStateOf("") }

                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    topBar = { ScamTopBar() }
                ) { innerPadding ->
                    ScamDashboard(
                        modifier = Modifier.padding(innerPadding),
                        messages = messages,
                        currentLanguage = currentLanguage,
                        mentorInitialQuestion = mentorQuestion,
                        onLanguageChange = { newLang ->
                            getSharedPreferences("scam_prefs", Context.MODE_PRIVATE)
                                .edit().putString("user_language", newLang).apply()
                            currentLanguage = newLang
                        },
                        onActivateShield = { requestDefaultSmsRole() },
                        onOpenNotificationSettings = { openNotificationAccessSettings() },
                        onScanInbox = { viewModel.scanInbox() },
                        onDelete = { msg -> 
                            Toast.makeText(this, "Reporting threat to community database...", Toast.LENGTH_SHORT).show()
                            ScamUtils.deleteFromSystemInbox(this, msg.sender, msg.body, msg.externalId)
                            viewModel.deleteMessage(msg)
                        },
                        onAllow = { msg ->
                            scope.launch {
                                db.scamDao().addToWhitelist(ScamWhitelist(msg.sender))
                                ScamUtils.restoreToInbox(this@MainActivity, msg.sender, msg.body)
                                viewModel.deleteMessage(msg)
                                Toast.makeText(this@MainActivity, "${msg.sender} added to whitelist.", Toast.LENGTH_SHORT).show()
                            }
                        },
                        onAskMentorAbout = { msg ->
                            mentorQuestion = "Explain why this message from '${msg.sender}' is a scam. Content: ${msg.fullContent}"
                        }
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val data: Uri? = intent?.data
        if (data != null && data.scheme == "scamguard" && data.host == "setup") {
            val chatId = data.getQueryParameter("id")
            if (chatId != null) {
                getSharedPreferences("scam_prefs", Context.MODE_PRIVATE)
                    .edit().putString("chat_id", chatId).apply()
                Toast.makeText(this, "✅ Telegram ID Link Successful!", Toast.LENGTH_LONG).show()
                recreate()
            }
        }
    }

    private fun setupThreatDatabaseRefresh() {
        val refreshRequest = PeriodicWorkRequestBuilder<ThreatRefreshWorker>(1, TimeUnit.DAYS)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork("ThreatDatabaseRefresh", ExistingPeriodicWorkPolicy.REPLACE, refreshRequest)
    }

    private fun requestDefaultSmsRole() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager = getSystemService(RoleManager::class.java)
            if (roleManager?.isRoleAvailable(RoleManager.ROLE_SMS) == true) {
                val intent = roleManager.createRequestRoleIntent(RoleManager.ROLE_SMS)
                requestRoleLauncher.launch(intent)
            }
        }
    }

    private fun openNotificationAccessSettings() {
        try { startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)) } catch (e: Exception) {}
    }

    private fun checkAndRequestPermissions() {
        val missingPermissions = permissionsToRequest.filter { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }
        if (missingPermissions.isNotEmpty()) requestPermissionsLauncher.launch(missingPermissions.toTypedArray())
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScamTopBar() {
    CenterAlignedTopAppBar(
        title = { Text("🛡️ SCAM-SHIELD AI", fontWeight = FontWeight.ExtraBold, color = Color.Black) },
        colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
            containerColor = Color(0xFFFFEBEE),
            titleContentColor = Color.Black
        )
    )
}

@Composable
fun ScamDashboard(
    modifier: Modifier = Modifier,
    messages: List<ScamMessage>,
    currentLanguage: String,
    mentorInitialQuestion: String,
    onLanguageChange: (String) -> Unit,
    onActivateShield: () -> Unit,
    onOpenNotificationSettings: () -> Unit,
    onScanInbox: () -> Unit,
    onDelete: (ScamMessage) -> Unit,
    onAllow: (ScamMessage) -> Unit,
    onAskMentorAbout: (ScamMessage) -> Unit
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var question by remember { mutableStateOf("") }
    
    LaunchedEffect(mentorInitialQuestion) {
        if (mentorInitialQuestion.isNotEmpty()) {
            question = mentorInitialQuestion
        }
    }

    Column(modifier = modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
        
        // --- 1. SECURITY ANALYTICS DASHBOARD ---
        Card(
            modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1B5E20)),
            elevation = CardDefaults.cardElevation(8.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("📊 PROTECTION ANALYTICS", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                Spacer(Modifier.height(8.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Column {
                        Text("Scams Blocked", color = Color.White.copy(alpha = 0.7f), fontSize = 10.sp)
                        Text("${messages.size}", color = Color.White, fontWeight = FontWeight.ExtraBold, fontSize = 24.sp)
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text("Est. Money Saved", color = Color.White.copy(alpha = 0.7f), fontSize = 10.sp)
                        Text("$${messages.size * 50}", color = Color(0xFF81C784), fontWeight = FontWeight.ExtraBold, fontSize = 24.sp)
                    }
                }
                Spacer(Modifier.height(8.dp))
                LinearProgressIndicator(
                    progress = { 0.85f },
                    modifier = Modifier.fillMaxWidth().height(4.dp),
                    color = Color(0xFF81C784),
                    trackColor = Color.White.copy(alpha = 0.2f)
                )
                Text("Privacy Shield: ON (Gemma AI Active)", color = Color.White.copy(alpha = 0.9f), fontSize = 10.sp, modifier = Modifier.padding(top = 4.dp))
            }
        }

        // --- 2. TELEGRAM ALERT SYNC (RESTORED) ---
        Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = Color(0xFFE1F5FE))) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("📢 TELEGRAM ALERT SYNC", fontWeight = FontWeight.Bold, color = Color.Black, fontSize = 14.sp)
                Text("Get alerts on your phone when a scam is detected.", fontSize = 11.sp, color = Color.Black)
                
                val prefs = remember { context.getSharedPreferences("scam_prefs", Context.MODE_PRIVATE) }
                var chatId by remember { mutableStateOf(prefs.getString("chat_id", "") ?: "") }

                OutlinedTextField(
                    value = chatId,
                    onValueChange = { chatId = it },
                    label = { Text("Enter Your Chat ID", color = Color.Gray) },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    textStyle = TextStyle(color = Color.Black),
                    colors = OutlinedTextFieldDefaults.colors(focusedTextColor = Color.Black, unfocusedTextColor = Color.Black)
                )
                
                Row(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                    Button(onClick = {
                        prefs.edit().putString("chat_id", chatId).apply()
                        Toast.makeText(context, "ID Saved!", Toast.LENGTH_SHORT).show()
                    }, modifier = Modifier.weight(1f)) { Text("SAVE ID", fontSize = 10.sp) }
                    
                    Spacer(Modifier.width(8.dp))
                    
                    OutlinedButton(onClick = {
                        val tgUri = Uri.parse("tg://resolve?domain=userinfobot")
                        try { context.startActivity(Intent(Intent.ACTION_VIEW, tgUri)) }
                        catch (e: Exception) { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/userinfobot"))) }
                    }, modifier = Modifier.weight(1f)) { Text("GET ID", fontSize = 10.sp, color = Color.Black) }
                }
                
                TextButton(
                    onClick = {
                        val tgUri = Uri.parse("tg://resolve?domain=ScamGuard_ASEAN_Bot")
                        try { context.startActivity(Intent(Intent.ACTION_VIEW, tgUri)) }
                        catch (e: Exception) { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/ScamGuard_ASEAN_Bot"))) }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("🤖 Connect to @ScamGuard_ASEAN_Bot", fontSize = 11.sp)
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        // --- 3. LANGUAGE PREFERENCE ---
        Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF3E0))) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("🌐 LANGUAGE PREFERENCE", fontWeight = FontWeight.Bold, color = Color.Black, fontSize = 14.sp)
                val languages = listOf("English", "Thai", "Burmese", "Vietnamese", "Indonesian", "Malay", "Khmer", "Lao", "Tagalog", "Tamil", "Chinese", "Japanese")
                var expanded by remember { mutableStateOf(false) }
                Box {
                    OutlinedButton(onClick = { expanded = true }, modifier = Modifier.fillMaxWidth()) { Text(currentLanguage, color = Color.Black) }
                    DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                        languages.forEach { lang -> DropdownMenuItem(text = { Text(lang) }, onClick = { onLanguageChange(lang); expanded = false }) }
                    }
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        // --- 4. MENTOR & FORENSIC CHAT ---
        Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = Color(0xFFF3E5F5))) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("🤖 AI FORENSIC MENTOR", fontWeight = FontWeight.Bold, color = Color.Black, fontSize = 14.sp)
                var answer by remember { mutableStateOf("") }
                var isLoading by remember { mutableStateOf(false) }
                
                OutlinedTextField(
                    value = question, 
                    onValueChange = { question = it }, 
                    modifier = Modifier.fillMaxWidth().background(Color.White, RoundedCornerShape(8.dp)),
                    textStyle = TextStyle(color = Color.Black),
                    placeholder = { Text("Analyze a suspicious link or text...", color = Color.Gray) },
                    colors = OutlinedTextFieldDefaults.colors(focusedTextColor = Color.Black, unfocusedTextColor = Color.Black, focusedBorderColor = Color.Black)
                )
                
                if (answer.isNotEmpty()) {
                    Box(modifier = Modifier.padding(top = 8.dp).fillMaxWidth().background(Color.White, RoundedCornerShape(8.dp)).padding(12.dp)) {
                        Text(answer, fontSize = 13.sp, color = Color.Black)
                    }
                }
                
                Button(
                    onClick = {
                        scope.launch {
                            isLoading = true
                            answer = "AI is analyzing..."
                            answer = GemmaAnalyzer.askMentor(context, question, currentLanguage) ?: "Error"
                            isLoading = false
                        }
                    }, 
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp), 
                    enabled = !isLoading,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF7B1FA2))
                ) {
                    if (isLoading) CircularProgressIndicator(modifier = Modifier.size(16.dp), color = Color.White) 
                    else Text("💬 GET AI ANALYSIS", color = Color.White)
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        // --- 5. SYSTEM ACTIONS ---
        Row(modifier = Modifier.fillMaxWidth()) {
            Button(onClick = onOpenNotificationSettings, modifier = Modifier.weight(1f)) { Text("🛡️ SHIELD ON", fontSize = 10.sp) }
            Spacer(Modifier.width(8.dp))
            Button(onClick = onScanInbox, modifier = Modifier.weight(1f), colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2E7D32))) { 
                Text("🔍 SCAN INBOX", fontSize = 10.sp, color = Color.White) 
            }
        }

        Spacer(Modifier.height(24.dp))
        Text("🚨 QUARANTINED THREATS (${messages.size})", fontWeight = FontWeight.ExtraBold, color = Color.White, fontSize = 16.sp)

        messages.forEach { message ->
            ScamItem(message, { onAllow(message) }, { onDelete(message) }, { onAskMentorAbout(message) })
        }
    }
}

@Composable
fun ScamItem(message: ScamMessage, onAllow: () -> Unit, onDelete: () -> Unit, onAskMentor: () -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val context = LocalContext.current

    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp), elevation = CardDefaults.cardElevation(4.dp), onClick = { expanded = !expanded }) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(message.sender, fontWeight = FontWeight.Bold, color = Color.Red, modifier = Modifier.weight(1f))
                if (message.isQrCode) {
                    Icon(Icons.Default.QrCodeScanner, contentDescription = "QR Detected", tint = Color.Blue, modifier = Modifier.size(20.dp))
                }
            }
            Text(message.body, fontSize = 14.sp, color = Color.White)
            
            AnimatedVisibility(visible = expanded) {
                Column(modifier = Modifier.padding(top = 8.dp)) {
                    if (message.websitePreview != null) {
                        Box(modifier = Modifier.fillMaxWidth().background(Color(0xFFE8F5E9), RoundedCornerShape(4.dp)).padding(8.dp)) {
                            Column {
                                Text("🌐 SAFE PREVIEW (LIVE SCAN)", fontWeight = FontWeight.Bold, fontSize = 10.sp, color = Color(0xFF2E7D32))
                                Text(message.websitePreview, fontSize = 11.sp, color = Color.Black)
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                    }

                    Text("💡 AI FORENSIC EXPLANATION", fontWeight = FontWeight.ExtraBold, fontSize = 12.sp, color = Color(0xFF81C784))
                    Text(text = message.explanation, fontSize = 13.sp, color = Color.White, modifier = Modifier.padding(vertical = 4.dp))
                    
                    OutlinedButton(onClick = onAskMentor, modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Default.Chat, contentDescription = null, modifier = Modifier.size(16.dp), tint = Color.Black)
                        Spacer(Modifier.width(8.dp))
                        Text("❓ WHY IS THIS A SCAM?", color = Color.Black)
                    }

                    if (message.packageName.isNotEmpty()) {
                        Button(onClick = {
                            try {
                                val cachedIntent = ScamNotificationListener.intentCache[message.externalId?.toInt()]
                                if (cachedIntent != null) cachedIntent.send()
                                else context.packageManager.getLaunchIntentForPackage(message.packageName)?.let { context.startActivity(it) }
                            } catch (e: Exception) {
                                context.packageManager.getLaunchIntentForPackage(message.packageName)?.let { context.startActivity(it) }
                            }
                        }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp), colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1E88E5))) {
                            Icon(Icons.AutoMirrored.Filled.OpenInNew, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("🔗 VIEW IN SOURCE APP")
                        }
                    }
                }
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                TextButton(onClick = onDelete) { Text("🗑️ DISMISS & REPORT", color = Color.Gray, fontSize = 11.sp) }
                TextButton(onClick = onAllow) { 
                    Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(16.dp), tint = Color(0xFF2E7D32))
                    Text("✅ TRUST SENDER", color = Color(0xFF2E7D32), fontSize = 11.sp)
                }
            }
        }
    }
}
