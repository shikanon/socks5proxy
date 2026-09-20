package com.shikanon.socks5proxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;

import org.json.JSONObject;

import com.shikanon.socks5proxy.core.mobile.Client;
import com.shikanon.socks5proxy.core.mobile.Mobile;

public final class TunnelVpnService extends VpnService {
    public static final String STOP = "com.shikanon.socks5proxy.STOP";
    public static volatile String status = "未连接";
    public static volatile boolean active = false;
    private final Object lock = new Object();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private Client client;
    private ParcelFileDescriptor tun;
    private long generation;

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || STOP.equals(intent.getAction())) {
            stopTunnel("未连接");
            stopSelf();
            return START_NOT_STICKY;
        }
        String config = intent.getStringExtra("config");
        if (config == null) {
            stopSelf();
            return START_NOT_STICKY;
        }
        synchronized (lock) {
            if (active) return START_NOT_STICKY;
            active = true;
            status = "正在连接…";
            generation++;
        }
        showNotification(status);
        long current;
        synchronized (lock) { current = generation; }
        new Thread(() -> connect(config, current), "vpn-connect").start();
        return START_NOT_STICKY;
    }

    private void connect(String config, long current) {
        Client local = null;
        try {
            local = Mobile.newClient(config, fd -> protect((int) fd));
            synchronized (lock) {
                if (current != generation) { local.close(); return; }
                client = local; // Publish before Connect so Stop cancels authentication.
            }
            JSONObject p = new JSONObject(local.connect());
            synchronized (lock) {
                if (current != generation) return;
                tun = new Builder()
                    .setSession("Socks5Proxy")
                    .setMtu(p.getInt("mtu"))
                    .addAddress(p.getString("client_ipv4"), 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer(p.getString("dns_ipv4"))
                    .setBlocking(false)
                    // No IPv6 family/address/route: Android blocks unsupported IPv6.
                    .establish();
                if (tun == null) throw new IllegalStateException("VPN 授权已撤销");
                local.attachFD(tun.getFd());
                local.start();
                status = "已连接";
            }
            handler.post(this::pollStatus);
        } catch (Exception error) {
            if (local != null) {
                try { local.close(); } catch (Exception ignored) { }
            }
            handler.post(() -> {
                synchronized (lock) {
                    if (current != generation) return;
                    stopTunnel("连接失败：" + error.getMessage());
                    stopSelf();
                }
            });
        }
    }

    private void pollStatus() {
        synchronized (lock) {
            if (client == null || !active) return;
            try {
                JSONObject result = new JSONObject(client.status());
                String state = result.getString("state");
                if ("error".equals(state) || "closed".equals(state)) {
                    stopTunnel("连接已停止：" + result.optString("error"));
                    stopSelf();
                    return;
                }
                status = "reconnecting".equals(state)
                    ? "正在重连，流量保持阻断"
                    : "已连接 · ↑ " + result.optLong("sent_bytes") / 1024 + " KB  ↓ "
                        + result.optLong("received_bytes") / 1024 + " KB";
                showNotification(status);
            } catch (Exception error) {
                stopTunnel("状态读取失败：" + error.getMessage());
                stopSelf();
                return;
            }
        }
        handler.postDelayed(this::pollStatus, 1500);
    }

    private void showNotification(String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(
            "vpn", "VPN 连接", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0,
            new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop = PendingIntent.getService(this, 1,
            new Intent(this, TunnelVpnService.class).setAction(STOP),
            PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification notification = new Notification.Builder(this, "vpn")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Socks5Proxy").setContentText(text).setContentIntent(open)
            .setOngoing(true).addAction(new Notification.Action.Builder(
                null, "断开", stop).build()).build();
        startForeground(1, notification);
    }

    private void stopTunnel(String message) {
        synchronized (lock) {
            generation++;
            active = false;
            handler.removeCallbacksAndMessages(null);
            if (client != null) {
                try { client.close(); } catch (Exception ignored) { }
                client = null;
            }
            if (tun != null) {
                try { tun.close(); } catch (Exception ignored) { }
                tun = null;
            }
            status = message;
            stopForeground(STOP_FOREGROUND_REMOVE);
        }
    }

    @Override public void onRevoke() {
        stopTunnel("VPN 授权已撤销");
        stopSelf();
    }

    @Override public void onDestroy() {
        stopTunnel(active ? "未连接" : status);
        super.onDestroy();
    }
}
