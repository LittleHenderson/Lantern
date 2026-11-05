package com.example.trips

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import com.example.trips.data.TripRepository

class TripActivity : AppCompatActivity() {
    private val repo = TripRepository()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val id = intent.data?.getQueryParameter("id") ?: return
        show(id)
    }

    private fun show(id: String) {
        val trip = repo.find(id)
        Log.d("Trips", "showing $trip")
    }
}
