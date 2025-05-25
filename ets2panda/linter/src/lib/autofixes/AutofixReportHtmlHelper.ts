/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export const AUTOFIX_HTML_TEMPLATE_TEXT = 'this is replace content';
export const AutofixHtmlTemplate = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>AutoFixes</title>
  <style>
    .safe-text-container {
        width: 80%;
        margin: 20px auto;
        padding: 15px;
        border: 1px solid #ddd;
        border-radius: 4px;
        background-color: #f8f9fa;
        white-space: pre-wrap;
        word-break: break-word;
        font-family: monospace;
        line-height: 1.5;
    }
  </style>
</head>
<body>
<div class="safe-text-container" id="content"></div>

<script>
  const rawContent =
\`${AUTOFIX_HTML_TEMPLATE_TEXT}\`; // replace it.
  const container = document.getElementById('content');
  container.textContent = rawContent;
</script>
</body>
</html>`;
