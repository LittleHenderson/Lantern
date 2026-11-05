package com.example.notes;

import android.content.SharedPreferences;
import android.location.Location;
import android.location.LocationManager;
import android.os.Bundle;
import android.telephony.SmsManager;
import android.util.Log;
import android.webkit.WebView;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "Notes";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView web = new WebView(this);
        web.getSettings().setJavaScriptEnabled(true);
        web.getSettings().setAllowUniversalAccessFromFileURLs(true);
        web.addJavascriptInterface(new Bridge(), "notes");
        web.loadUrl("http://notes.example.org/help");
        setContentView(web);
        saveLogin("abc");
    }

    void saveLogin(String token) {
        SharedPreferences prefs = getSharedPreferences("notes", MODE_PRIVATE);
        prefs.edit().putString("auth_token", token).apply();
    }

    public void onShareClicked() {
        LocationManager lm = (LocationManager) getSystemService(LOCATION_SERVICE);
        Location here = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
        Log.d(TAG, "sharing location " + here.getLatitude() + "," + here.getLongitude());
        SmsManager.getDefault().sendTextMessage("5550100", null, "I am here", null, null);
    }

    static class Bridge {
        public String hello() { return "hi"; }
    }
}
