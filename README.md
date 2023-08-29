# Redacted Request Extension for Burp Suite

## Description

The **Redacted Request Extension** is a powerful tool designed to enhance the security and confidentiality of HTTP request handling within the Burp Suite. Developed by **OME MISHRA**, this extension serves as a protective layer against inadvertent exposure of sensitive information present in headers such as cookies, authorization tokens, and security tokens.

## Key Features

- **Confidentiality Enhancement:** This extension acts as a safeguard for confidential information by redacting sensitive headers within selected HTTP requests.
  
- **Effortless Integration:** Seamlessly integrated into the Burp Suite, the extension adds a context menu option for users to redact and copy modified requests.
  
- **Customizable Redaction:** When the user selects "Copy Redacted Request," the extension automatically replaces sensitive headers with placeholders such as "REDACTED." This ensures that no sensitive data is inadvertently exposed.
  
- **Intelligent Redaction:** The extension specifically targets the `Cookie`, `Authorization`, and `X-Amz-Security-Token` headers, which are commonly used to carry sensitive information.
  
- **Clipboard Convenience:** After redacting the headers, the modified request is copied to the clipboard, offering a seamless experience for users to proceed with secure analysis and testing.

## Usage Guide

1. **Installation:** Load the extension within the Burp Suite environment.
  
2. **Redacting Requests:** While working in the Repeater tool, right-click on an HTTP request that contains sensitive headers.
  
3. **Select "Redacted Request":** Choose the "Copy Redacted Request" option from the context menu.
  
4. **Instant Redaction:** The extension will promptly redact the sensitive headers in the selected request.
  
5. **Secure Clipboard Copy:** The modified request, now devoid of sensitive information, is copied to the clipboard. Paste the redacted request securely into your workflow.

## About the Author

**OME MISHRA** is the creator of this innovative extension. With a keen focus on enhancing data security within Burp Suite, this tool will empowers users to work confidently with HTTP requests containing sensitive information.

## Version Information

This is version 1.0 of the Redacted Request Extension.

## Copyright Notice

© 2023 OME MISHRA. All rights reserved. Unauthorized copying or distribution of this extension's code is strictly prohibited by law.

## Disclaimer

This extension is provided for educational and security purposes. The author does not endorse or assume responsibility for any misuse, unintended consequences, or damages resulting from the use of this extension. Users are encouraged to apply this tool responsibly and within legal boundaries.

For any inquiries or feedback, please contact OME MISHRA at [https://omemishra.me].

