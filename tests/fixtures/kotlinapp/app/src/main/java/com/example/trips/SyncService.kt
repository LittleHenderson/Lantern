package com.example.trips

import android.app.Service
import android.content.Intent
import android.os.IBinder
import com.example.trips.data.Api
import com.example.trips.data.HttpApi

class SyncService : Service() {
    private val api: Api = HttpApi()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        api.upload("all")
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
