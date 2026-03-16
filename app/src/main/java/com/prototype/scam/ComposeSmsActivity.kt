package com.prototype.scam

import android.app.Activity
import android.os.Bundle

class ComposeSmsActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // This is a requirement for being a default SMS app.
        // Even if empty, it must exist.
        finish()
    }
}