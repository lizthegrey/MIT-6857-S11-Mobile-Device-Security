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

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

public class AuthOpenHelper extends SQLiteOpenHelper {

  private static final String DATABASE_NAME =
    "com.google.mobile.security.permissionsproxy";
  private static final int DATABASE_VERSION = 1;

  public static final String AUTH_TABLE_NAME = "auth";
  public static final String URL = "url";
  public static final String APPS = "apps";
  public static final String STATUS = "status";
  public static final String EXPIRATION = "expiration";

  private static final String AUTH_TABLE_CREATE =
              "CREATE TABLE " + AUTH_TABLE_NAME + " (" +
              URL + " TEXT, " +
              APPS + " TEXT, " +
              STATUS + " TEXT, " +
              EXPIRATION + " INT);";

  public AuthOpenHelper(Context context) {
      super(context, DATABASE_NAME, null, DATABASE_VERSION);
  }

  @Override
  public void onCreate(SQLiteDatabase db) {
      db.execSQL(AUTH_TABLE_CREATE);
  }

  @Override
  public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
    // TODO Auto-generated method stub
  }
}
