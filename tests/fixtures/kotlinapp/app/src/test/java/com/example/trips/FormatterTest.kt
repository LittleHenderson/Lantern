package com.example.trips

import com.example.trips.data.Formatter
import org.junit.Assert.assertEquals
import org.junit.Test

class FormatterTest {
    @Test
    fun namesAreTrimmed() {
        assertEquals(listOf("a"), Formatter.names(listOf(" a ")))
    }
}
