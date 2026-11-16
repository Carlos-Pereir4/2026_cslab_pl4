Here is a static security review of the provided Flask application.

### Findings Summary

| ID | Title | Severity |
| --- | --- | --- |
| F1 | Hardcoded Cryptographic Secret Key | High |
| F2 | Path Traversal in File Download | High |
| F3 | Missing Authentication on Data Retrieval (BOLA/IDOR) | High |
| F4 | Missing Access Control on Grade Modification | High |
| F5 | Flask Debug Mode Enabled | High |
| F6 | Plaintext Password Storage | Medium |
| F7 | Information Exposure in Global Error Handler | Low |

---

### Detailed Findings

**F1: Hardcoded Cryptographic Secret Key**

1. **Identifier and title:** F1 - Hardcoded Cryptographic Secret Key
2. **Location:** `app.py`, global scope, line 7.
3. **Attacker-controlled input and execution path:** An attacker can read the source code to obtain the plaintext `SECRET_KEY`. They can then use this key locally to sign malicious session cookies and submit them to the server via standard HTTP requests.
4. **Missing control and root cause:** The application lacks secure configuration management. The root cause is embedding sensitive cryptographic material directly in the source code rather than provisioning it via environment variables or a secure vault.
5. **Preconditions and impact:** The attacker only requires network access to the application. The impact is a complete authentication bypass because the attacker can forge a valid session cookie for any user including administrators.
6. **Proposed test:** Forge a Flask session cookie locally using the "dev-secret-key" string to set the user role to "admin" and send this cookie in a GET request to the `/me` endpoint.
7. **Assumptions, uncertainty and confidence:** I assume this codebase represents the configuration intended for deployment. I hold high confidence in this finding due to the explicit nature of the assignment.

**F2: Path Traversal in File Download**

1. **Identifier and title:** F2 - Path Traversal in File Download
2. **Location:** `app.py`, `download_file` function, lines 96-98.
3. **Attacker-controlled input and execution path:** The user supplies a payload via the `path` query parameter. This input is appended directly to `MATERIALS_DIR` using the `/` operator from `pathlib.Path`. If the input is an absolute path (e.g. `/etc/passwd`), Python's `pathlib` discards the left operand and resolves exclusively to the attacker-supplied absolute path.
4. **Missing control and root cause:** The endpoint lacks input validation and path normalization. The root cause is the unsafe concatenation of untrusted user input into a filesystem path without verifying that the final resolved path remains confined within the intended directory constraint.
5. **Preconditions and impact:** The attacker requires network access to the `/files` endpoint. The impact is arbitrary file read capabilities across the host operating system.
6. **Proposed test:** Send a GET request to `/files?path=/etc/passwd` and observe if the server responds with the contents of the system password file.
7. **Assumptions, uncertainty and confidence:** I assume the application runs with sufficient operating system privileges to read the targeted files. I have high confidence in this vulnerability due to the well-documented behaviour of `pathlib`.

**F3: Missing Authentication on Data Retrieval (BOLA/IDOR)**

1. **Identifier and title:** F3 - Missing Authentication on Data Retrieval (BOLA/IDOR)
2. **Location:** `app.py`, `get_profile` (lines 71-75) and `get_grades` (lines 77-80).
3. **Attacker-controlled input and execution path:** An attacker manipulates the `student_id` variable in the URL path for either endpoint. The application uses this input to fetch records directly from the `STUDENT_PROFILES` or `GRADES` dictionaries.
4. **Missing control and root cause:** The endpoints lack session validation and Object-Level Authorization. The root cause is the failure to verify both the authentication state of the requester and their authorization rights regarding the requested object.
5. **Preconditions and impact:** Network access to the API endpoints. The impact is the unfettered disclosure of sensitive personal identifiable information and academic records for all enrolled students.
6. **Proposed test:** Send an unauthenticated GET request to `/students/1002/profile` from an anonymous HTTP client and verify that Bob's profile data is successfully returned.
7. **Assumptions, uncertainty and confidence:** I assume academic grades and student profiles are considered confidential by institutional policy. I hold high confidence in this finding.

**F4: Missing Access Control on Grade Modification**

1. **Identifier and title:** F4 - Missing Access Control on Grade Modification
2. **Location:** `app.py`, `update_grade` function, lines 82-93.
3. **Attacker-controlled input and execution path:** The attacker submits a JSON payload containing `student_id`, `course_id` and `grade` to the POST endpoint. The application extracts these values and modifies the `GRADES` array in memory.
4. **Missing control and root cause:** The application lacks Function-Level Access Control. The root cause is accepting state-changing requests without checking if a valid session exists and if the authenticated entity possesses the requisite privileges (e.g. verifying the user is a professor).
5. **Preconditions and impact:** Network access. The impact is catastrophic to the integrity of the academic system since any individual can alter or fabricate grades.
6. **Proposed test:** Send an unauthenticated POST request to `/grades/update` attempting to change student 1001's grade for the "SRS" course to 20 and then query `/grades/1001` to confirm the modification.
7. **Assumptions, uncertainty and confidence:** I assume students should not possess the authorization to assign or alter academic grades. I have high confidence in this assessment.

**F5: Flask Debug Mode Enabled**

1. **Identifier and title:** F5 - Flask Debug Mode Enabled
2. **Location:** `app.py`, global scope, line 111.
3. **Attacker-controlled input and execution path:** An attacker purposefully triggers an unhandled exception in the application to summon the interactive Werkzeug debugger in the browser.
4. **Missing control and root cause:** The environment lacks segregation between development and production configurations. The root cause is hardcoding `debug=True` within the application startup sequence.
5. **Preconditions and impact:** The application must be deployed using this specific conditional block. The impact is potential Remote Code Execution because the debugger allows arbitrary Python code execution on the server.
6. **Proposed test:** Intentionally cause a server error (e.g. providing an invalid data type to the grade update endpoint) and attempt to access the web-based debugger console to execute a basic command like `print("exploit")`.
7. **Assumptions, uncertainty and confidence:** I assume this script might be executed as-is in a production environment. If it is only used locally for development, the risk is mitigated. Moderate confidence depending on deployment context.

**F6: Plaintext Password Storage**

1. **Identifier and title:** F6 - Plaintext Password Storage
2. **Location:** `app.py`, `USERS` dictionary, lines 25-32.
3. **Attacker-controlled input and execution path:** This vulnerability does not rely on a direct execution path from user input. It exacerbates the severity of secondary attacks.
4. **Missing control and root cause:** The application lacks cryptographic password hashing. The root cause is the deliberate storage of authentication credentials as plaintext strings within process memory.
5. **Preconditions and impact:** An attacker must first achieve local file read (via F2) or memory access. The impact is immediate credential theft enabling subsequent lateral movement or privilege escalation.
6. **Proposed test:** Inspect the source file directly or trigger a memory dump to verify that the string "alicepw" is visible without decryption.
7. **Assumptions, uncertainty and confidence:** I assume the hardcoded dictionary represents the intended credential management strategy for this prototype. High confidence.

**F7: Information Exposure in Global Error Handler**

1. **Identifier and title:** F7 - Information Exposure in Global Error Handler
2. **Location:** `app.py`, `handle_error` function, lines 102-107.
3. **Attacker-controlled input and execution path:** The attacker submits erroneous input (such as an empty payload to a JSON endpoint) causing the application to raise an exception. The global error handler catches this and reflects the raw exception text back to the client.
4. **Missing control and root cause:** Missing sanitized error messages. The root cause is casting the raw system exception to a string and returning it in the HTTP response.
5. **Preconditions and impact:** The attacker needs the ability to trigger application exceptions. The impact is the disclosure of internal application state or filesystem paths which aids reconnaissance efforts.
6. **Proposed test:** Send a POST request to `/grades/update` without a JSON body to force an exception and observe if the response includes internal framework error details.
7. **Assumptions, uncertainty and confidence:** I assume the application policy mandates obscuring technical details from end users. High confidence.
