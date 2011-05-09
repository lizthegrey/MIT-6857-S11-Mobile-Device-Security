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

import java.net.URL;
import java.util.Arrays;

import com.google.mobile.security.permissionsproxy.ProxyService.Auth;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

public class ApproveRequest extends Activity {

  /** Called when the activity is first created. */
  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.approve);
    Intent i = getIntent();
    final URL u =
      (URL)i.getSerializableExtra(ProxyService.PERMISSIONSPROXY_URL);
    String[] c = i.getStringArrayExtra(ProxyService.PERMISSIONSPROXY_CALLER);
    final String apps = Arrays.toString(c);
    TextView req = (TextView)findViewById(R.id.req);
    Button approve_15 = (Button)findViewById(R.id.approve_15);
    Button deny_15 = (Button)findViewById(R.id.deny_15);
    Button approve_60 = (Button)findViewById(R.id.approve_60);
    Button deny_60 = (Button)findViewById(R.id.deny_60);
    req.setText("The applications " + apps +
      " would like to access the URL " + u);
    approve_15.setOnClickListener(
        new AclUpdater(u.toString(), apps, Auth.PERMITTED, 15));
    deny_15.setOnClickListener(
      new AclUpdater(u.toString(), apps, Auth.DENIED, 15));
    approve_60.setOnClickListener(
        new AclUpdater(u.toString(), apps, Auth.PERMITTED, 60));
    deny_60.setOnClickListener(
      new AclUpdater(u.toString(), apps, Auth.DENIED, 60));
  }

  class AclUpdater implements OnClickListener {
    private Auth type;
    private int duration;
    private String url;
    private String apps;

    public AclUpdater(String url, String apps, Auth type, int duration) {
      this.url = url;
      this.apps = apps;
      this.type = type;
      this.duration = duration;
    }

    @Override
    public void onClick(View v) {
      AuthOpenHelper helper = new AuthOpenHelper(ApproveRequest.this);
      SQLiteDatabase db = helper.getWritableDatabase();
      db.delete(AuthOpenHelper.AUTH_TABLE_NAME,
          AuthOpenHelper.APPS + " = ? AND " +
          AuthOpenHelper.URL + " = ? AND " +
          AuthOpenHelper.STATUS + " = ?", 
        new String[] {apps, url, Auth.IN_PROGRESS.toString()});
      // Insert a denied record good for 120 seconds.
      ContentValues vals = new ContentValues();
      vals.put(AuthOpenHelper.URL, url);
      vals.put(AuthOpenHelper.APPS, apps);
      vals.put(AuthOpenHelper.STATUS, type.toString());
      vals.put(AuthOpenHelper.EXPIRATION,
        (System.currentTimeMillis() / 1000) + duration);
      db.insert(AuthOpenHelper.AUTH_TABLE_NAME, null, vals);
      db.close();
      finish();
    }
  }
}
