// Copyright (c) 2011 Google, Inc.
// Author: Liz Fong <lizf@google.com>
//
// Licensed under the Apache License, Version 2.0 (the "License")
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.mobile.security.permissionsproxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import android.app.Service;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Binder;
import android.os.IBinder;

public class ProxyService extends Service {

  public static final String PERMISSIONSPROXY_CALLER =
    "com.google.mobile.security.permissionsproxy.caller";
  public static final String PERMISSIONSPROXY_URL =
    "com.google.mobile.security.permissionsproxy.url";
  public static final String RETRY = "RETRY_REQUEST_LATER";

  private static final String SAFEBROWSING_API_KEY =
    "ABQIAAAAj4piHlHGaDzB_Aum81lGrxT1r2rDoIx15e1KtJkQdU-v-O0Ucg";
  private static final String HTTP_POST = "POST";

  public enum Auth {
    IN_PROGRESS,
    DENIED,
    PERMITTED,
    NEVER_SEEN
  }

  @Override
  public void onCreate() {
    super.onCreate();
  }

  @Override
  public IBinder onBind(Intent intent) {
    return mBinder;
  }

  private final ProxyServiceInterface.Stub mBinder =
    new ProxyServiceInterface.Stub() {
      @SuppressWarnings("unchecked")
      @Override
      public byte[] getUrl(String url, Map headers, List<String> err) {
        return doRequest(url, (Map<String, String>)headers, null,
          getApplicationContext(), ProxyService.this, err);
      }
      @SuppressWarnings("unchecked")
      @Override
      public byte[] postUrl(String url, Map headers, String postBody,
          List<String> err) {
        return doRequest(url, (Map<String, String>)headers, postBody,
          getApplicationContext(), ProxyService.this, err);
      }
    };

  private static byte[] doRequest(String url, Map<String, String> headers,
      String postBody, Context ctx, Service s, List<String> err) {
    try {
      if (!safebrowsingOkay(url, ctx)) {
        err.add(ctx.getString(R.string.safebrowsing));
        return null;
      }


      int callingUid = Binder.getCallingUid();
      String[] packageNames =
        ctx.getPackageManager().getPackagesForUid(callingUid);

      URL u = new URL(url);

      switch (isAuthorized(packageNames, url, ctx)) {
       case NEVER_SEEN:
        // Ask the user.
        Intent in = new Intent(ctx, ApproveRequest.class);
        in.putExtra(PERMISSIONSPROXY_URL, u);
        in.putExtra(PERMISSIONSPROXY_CALLER, packageNames);
        in.setFlags(Intent.FLAG_ACTIVITY_NO_HISTORY |
                    Intent.FLAG_ACTIVITY_NEW_TASK);
        s.startActivity(in);
       case IN_PROGRESS:
        // Busy wait while we evaluate.
        err.add(RETRY);
        return null;
       case DENIED:
        // Decline without popping up a dialog.
        err.add(ctx.getString(R.string.user_declined));
        return null;
      }

      HttpURLConnection conn =
        (HttpURLConnection)u.openConnection();
      if (postBody != null) {
        conn.setDoOutput(true);
        conn.setRequestMethod(HTTP_POST);
      }
      for (Map.Entry<String, String> header : headers.entrySet()) {
        conn.setRequestProperty(header.getKey(), header.getValue());
      }
      conn.connect();
      if (postBody != null) {
        OutputStreamWriter writer =
          new OutputStreamWriter(conn.getOutputStream());
        writer.write(postBody);
        writer.flush();
      }
      InputStream is = conn.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      byte[] buffer = new byte[1024];
      int len = is.read(buffer);
      while (len != -1) {
        os.write(buffer, 0, len);
        len = is.read(buffer);
      }
      is.close();
      os.close();
      return os.toByteArray();
    } catch (IOException ioe) {
      err.add(ctx.getString(R.string.io_error));
      return null;
    }
  }

  private static Auth isAuthorized(String[] packageNames, String url,
      Context ctx) {
    String apps = Arrays.toString(packageNames);
    AuthOpenHelper helper = new AuthOpenHelper(ctx);
    SQLiteDatabase db = helper.getWritableDatabase();
    Cursor c = db.query(AuthOpenHelper.AUTH_TABLE_NAME,
      new String[] {AuthOpenHelper.STATUS, AuthOpenHelper.EXPIRATION},
      AuthOpenHelper.EXPIRATION + " > ? AND " +
      AuthOpenHelper.APPS + " = ? AND " +
      AuthOpenHelper.URL + " = ?",
      new String[] {"" + System.currentTimeMillis() / 1000, apps, url},
      null, null,
      AuthOpenHelper.EXPIRATION + " ASC");
    if (c.moveToFirst()) {
      String status = c.getString(c.getColumnIndex(AuthOpenHelper.STATUS));
      Auth val = Auth.valueOf(status);
      c.close();
      db.close();
      return val;
    }
    c.close();
    // We've never been seen. Insert a never seen record good for 30 seconds.
    ContentValues vals = new ContentValues();
    vals.put(AuthOpenHelper.URL, url);
    vals.put(AuthOpenHelper.APPS, apps);
    vals.put(AuthOpenHelper.STATUS, Auth.IN_PROGRESS.toString());
    vals.put(AuthOpenHelper.EXPIRATION,
      (System.currentTimeMillis() / 1000) + 30);
    db.insert(AuthOpenHelper.AUTH_TABLE_NAME, null, vals);
    db.close();
    return Auth.NEVER_SEEN;
  }

  private static boolean safebrowsingOkay(String url, Context ctx)
      throws IOException {
    PackageManager manager = ctx.getPackageManager();
    PackageInfo info;
    String version = "unknown";
    try {
      info = manager.getPackageInfo(
        ctx.getPackageName(), 0);
      version = info.versionName;
    } catch (NameNotFoundException e) {
      // version will be unknown.
    }
    String safebrowsingUrl = String.format(
      "https://sb-ssl.google.com/safebrowsing/api/lookup?" +
      "client=permissions-proxy&apikey=%s&appver=%s&pver=3.0&url=%s",
      SAFEBROWSING_API_KEY, version, URLEncoder.encode(url));
    HttpURLConnection conn =
      (HttpURLConnection)(new URL(safebrowsingUrl)).openConnection();
    conn.connect();
    return (conn.getResponseCode() == HttpURLConnection.HTTP_NO_CONTENT);
  }
}
