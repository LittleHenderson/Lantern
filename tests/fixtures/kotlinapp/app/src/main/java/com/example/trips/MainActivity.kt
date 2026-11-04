package com.example.trips

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.example.trips.ui.TripListFragment

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showList()
    }

    private fun showList() {
        supportFragmentManager.beginTransaction().add(TripListFragment(), "list").commit()
    }

    fun openTrip(id: String) {
        startActivity(Intent(this, TripActivity::class.java).putExtra("id", id))
    }
}
