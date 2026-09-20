package com.shikanon.socks5proxy;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.text.InputType;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import org.json.JSONObject;

public final class MainActivity extends Activity {
    private EditText server, clientID, token, serverName, ca;
    private Spinner transport, obfs;
    private TextView state;
    private Button connect;
    private final Handler handler = new Handler();
    private String pendingConfig;
    private final Runnable refresh = new Runnable() {
        @Override public void run() {
            state.setText(TunnelVpnService.status);
            connect.setEnabled(!TunnelVpnService.active);
            handler.postDelayed(this, 1000);
        }
    };

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE,
            android.view.WindowManager.LayoutParams.FLAG_SECURE);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (24 * getResources().getDisplayMetrics().density);
        body.setPadding(padding, padding, padding, padding);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(body);
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            body.setPadding(padding + insets.getSystemWindowInsetLeft(),
                padding + insets.getSystemWindowInsetTop(),
                padding + insets.getSystemWindowInsetRight(),
                padding + insets.getSystemWindowInsetBottom());
            return insets;
        });
        setContentView(scroll);
        TextView title = new TextView(this);
        title.setText("Socks5Proxy");
        title.setTextSize(30);
        body.addView(title);
        TextView description = new TextView(this);
        description.setText("全局 IPv4 VPN · QUIC / TCP\n配置需与服务端一致，每台设备使用独立的客户端 ID。");
        body.addView(description);
        state = new TextView(this);
        state.setTextSize(18);
        state.setPadding(0, padding, 0, padding);
        body.addView(state);
        SharedPreferences prefs = getPreferences(MODE_PRIVATE);
        server = field(body, "服务器 host:port", prefs.getString("server", ""), false);
        clientID = field(body, "客户端 ID", prefs.getString("id", ""), false);
        token = field(body, "Token（至少 32 字符）", "", true);
        serverName = field(body, "TLS 服务器名称（可选）", prefs.getString("sni", ""), false);
        ca = field(body, "CA 证书 PEM（私有 CA 必填）", "", false);
        ca.setSingleLine(false);
        ca.setMinLines(3);
        ca.setMaxLines(6);
        ca.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE |
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        ca.setSaveEnabled(false);
        transport = choice(body, "传输协议", new String[]{"quic", "tcp", "tcp-plain"});
        obfs = choice(body, "混淆", new String[]{"none", "simple", "random"});
        TextView note = new TextView(this);
        note.setText("tcp 使用 TLS 1.3；tcp-plain 不加密。simple/random 混淆不能替代加密。\nToken 和 CA 仅在本次运行中保留。IPv6 被阻断。");
        body.addView(note);
        connect = new Button(this);
        connect.setText("连接 VPN");
        connect.setOnClickListener(v -> prepareVPN());
        body.addView(connect);
        Button stop = new Button(this);
        stop.setText("断开");
        stop.setOnClickListener(v -> {
            pendingConfig = null;
            startService(new Intent(this, TunnelVpnService.class).setAction(TunnelVpnService.STOP));
        });
        body.addView(stop);
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 2);
        }
    }

    private EditText field(LinearLayout body, String label, String value, boolean secret) {
        TextView caption = new TextView(this);
        caption.setText(label);
        body.addView(caption);
        EditText edit = new EditText(this);
        edit.setSingleLine(true);
        edit.setInputType(InputType.TYPE_CLASS_TEXT | (secret
            ? InputType.TYPE_TEXT_VARIATION_PASSWORD : InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS));
        edit.setText(value);
        edit.setSaveEnabled(!secret);
        body.addView(edit);
        return edit;
    }

    private Spinner choice(LinearLayout body, String label, String[] values) {
        TextView caption = new TextView(this);
        caption.setText(label);
        body.addView(caption);
        Spinner select = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, values);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        select.setAdapter(adapter);
        body.addView(select);
        return select;
    }

    private void prepareVPN() {
        try {
            String endpoint = server.getText().toString().trim();
            String id = clientID.getText().toString().trim();
            String secret = token.getText().toString().trim();
            if (endpoint.isEmpty() || id.isEmpty() || secret.length() < 32) {
                state.setText("请填写服务器、客户端 ID 和至少 32 字符的 Token");
                return;
            }
            pendingConfig = new JSONObject()
                .put("server_addr", endpoint).put("client_id", id).put("token", secret)
                .put("server_name", serverName.getText().toString().trim())
                .put("ca_pem", ca.getText().toString())
                .put("transport", transport.getSelectedItem().toString())
                .put("obfs", obfs.getSelectedItem().toString()).toString();
            getPreferences(MODE_PRIVATE).edit().putString("server", endpoint).putString("id", id)
                .putString("sni", serverName.getText().toString().trim()).apply();
            Intent consent = VpnService.prepare(this);
            if (consent != null) startActivityForResult(consent, 1);
            else startVPN();
        } catch (Exception error) {
            state.setText(error.getMessage());
        }
    }

    private void startVPN() {
        if (pendingConfig == null) return;
        startForegroundService(new Intent(this, TunnelVpnService.class).putExtra("config", pendingConfig));
        pendingConfig = null;
        token.setText("");
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == 1 && result == RESULT_OK) startVPN();
        else if (request == 1) {
            pendingConfig = null;
            state.setText("未获得 VPN 授权");
        }
    }

    @Override protected void onResume() {
        super.onResume();
        handler.post(refresh);
    }

    @Override protected void onPause() {
        handler.removeCallbacks(refresh);
        super.onPause();
    }
}
