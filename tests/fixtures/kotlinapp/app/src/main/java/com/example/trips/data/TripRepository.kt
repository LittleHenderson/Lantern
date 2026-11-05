package com.example.trips.data

class TripRepository {
    fun find(id: String): String? {
        val db = TripDatabase.get()
        val c = db.rawQuery("SELECT name FROM trips WHERE id = '" + id + "'", null)
        return if (c.moveToFirst()) c.getString(0) else null
    }

    fun all(): List<String> = Formatter.names(listOf("a"))

    companion object {
        fun make(): TripRepository = TripRepository()
    }
}
