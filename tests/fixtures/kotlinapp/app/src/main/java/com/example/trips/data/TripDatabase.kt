package com.example.trips.data

import android.content.Context
import android.database.sqlite.SQLiteDatabase

object TripDatabase {
    private var db: SQLiteDatabase? = null

    fun open(context: Context) {
        db = context.openOrCreateDatabase("trips.db", Context.MODE_PRIVATE, null)
    }

    fun get(): SQLiteDatabase = db!!
}
