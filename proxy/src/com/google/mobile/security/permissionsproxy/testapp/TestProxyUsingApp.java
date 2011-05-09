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

package com.google.mobile.security.permissionsproxy.testapp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import com.google.mobile.security.permissionsproxy.ProxyService;
import com.google.mobile.security.permissionsproxy.ProxyServiceInterface;
import com.google.mobile.security.permissionsproxy.R;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.RemoteException;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

public class TestProxyUsingApp extends Activity {
  /** The primary interface we will be calling on the service. */
  ProxyServiceInterface mService = null;

  Button google;
  Button phishing;
  TextView mHtml;

  /**
   * Standard initialization of this activity.  Set up the UI, then wait
   * for the user to poke it before doing anything.
   */
  @Override
  protected void onCreate(Bundle savedInstanceState) {
      super.onCreate(savedInstanceState);

    setContentView(R.layout.test_app);

    // Watch for button clicks.
    google = (Button)findViewById(R.id.google);
    google.setOnClickListener(mGoogleListener);
    phishing = (Button)findViewById(R.id.phishing);
    phishing.setOnClickListener(mPhishingListener);
    mHtml = (TextView)findViewById(R.id.html);
    mHtml.setText(getString(R.string.waiting));
    bindService(new Intent(ProxyServiceInterface.class.getName()),
      mConnection, Context.BIND_AUTO_CREATE);
  }

  @Override
  protected void onDestroy() {
    unbindService(mConnection);
    super.onDestroy();
  }

  private ServiceConnection mConnection = new ServiceConnection() {
    @Override
    public void onServiceConnected(ComponentName className,
        IBinder service) {
      // This is called when the connection with the service has been
      // established, giving us the service object we can use to
      // interact with the service.  We are communicating with our
      // service through an IDL interface, so get a client-side
      // representation of that from the raw service object.
      mService = ProxyServiceInterface.Stub.asInterface(service);
      mHtml.setText(getString(R.string.ready));
    }

    @Override
    public void onServiceDisconnected(ComponentName className) {
      // This is called when the connection with the service has been
      // unexpectedly disconnected -- that is, its process crashed.
      mService = null;
      mHtml.setText(getString(R.string.not_ready));
    }
  };

  private class UrlDispatcher implements OnClickListener {
    public UrlDispatcher(String url) {
      this.url = url;
    }
    private String url;

    @Override
    public void onClick(final View v) {
      if (mService != null) {
        try {
          List<String> err = new ArrayList<String>();
          byte[] ret = mService.getUrl(url, Collections.EMPTY_MAP, err);
          if (ret != null) {
            mHtml.setText(new String(ret));
          } else {
            if (err.get(0).equals(ProxyService.RETRY)) {
              final Handler handler = new Handler();
              Timer t = new Timer(); 
              t.schedule(new TimerTask() { 
                public void run() { 
                  handler.post(new Runnable() { 
                    public void run() { 
                     onClick(v);
                    }
                  });
                }
              }, 2000);
            }
            mHtml.setText(
              getText(R.string.security_exception) + err.toString());
          }
        } catch (RemoteException e) {
          mHtml.setText(getText(R.string.remote_error));
        }
      }
    }
  }

  private OnClickListener mPhishingListener =
    new UrlDispatcher("http://malware.testing.google.test/testing/malware/");
  private OnClickListener mGoogleListener =
    new UrlDispatcher("http://www.google.com/humans.txt");
}
