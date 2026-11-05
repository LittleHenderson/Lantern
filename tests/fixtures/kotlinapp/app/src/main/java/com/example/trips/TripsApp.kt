package com.example.trips

import android.app.Application
import com.example.trips.data.TripDatabase

class TripsApp : Application() {
    override fun onCreate() {
        super.onCreate()
        TripDatabase.open(this)
    }
}
