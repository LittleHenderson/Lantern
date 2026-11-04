package com.example.trips.data

import okhttp3.OkHttpClient
import okhttp3.Request

interface Api {
    fun upload(what: String)
}

class HttpApi : Api {
    private val client = OkHttpClient()

    override fun upload(what: String) {
        val req = Request.Builder().url("https://api.example.com/sync?what=$what").build()
        client.newCall(req).execute()
    }
}

class FakeApi : Api {
    override fun upload(what: String) {}
}

object Formatter {
    fun names(xs: List<String>): List<String> = xs.map(::clean)

    private fun clean(s: String) = s.trim()
}
