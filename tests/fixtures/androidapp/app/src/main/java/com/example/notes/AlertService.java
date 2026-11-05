package com.example.notes;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class AlertService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        sendBroadcast(new Intent("com.example.notes.ALERT_SENT"));
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
