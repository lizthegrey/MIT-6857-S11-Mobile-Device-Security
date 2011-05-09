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

import java.util.Map;

interface ProxyServiceInterface {
  /** Fetches a single URL over HTTP GET. */
  byte[] getUrl(String uri, in Map headers, out List<String> errorReason);
  /** Fetches a single URL over HTTP POST. */
  byte[] postUrl(String uri, in Map headers,
                 String postBody, out List<String> errorReason);
}
