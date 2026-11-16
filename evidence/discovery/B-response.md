### Findings Table

| Identifier | Title | Affected Location |
| --- | --- | --- |
| VULN-01 | Path Traversal in File Download | `download_file` (`/files`) |
| VULN-02 | Broken Object Level Authorization | `get_profile` and `get_grades` |
| VULN-03 | Unauthenticated Grade Modification | `update_grade` (`/grades/update`) |
| VULN-04 | Insecure Storage of Secrets and Credentials | Global Scope |
| VULN-05 | Information Disclosure in Error Handler | `handle_error` |

### Supporting Explanations

#### 1. VULN-01: Path Traversal in File Download

1. **Identifier and title:** VULN-01 Path Traversal in File Download
2. **Location:** `app.py`, `download_file` function, lines 105-108.
3. **Attacker-controlled input:** The `path` query parameter extracted via `flask.request.args.get("path", "")`. This input flows directly into a path concatenation operation (`MATERIALS_DIR / raw_path`) and is passed to `flask.send_file()`.
4. **Missing control and root cause:** Missing input validation and missing path normalization checks. The root cause is appending unsanitized user input directly to a base directory object without ensuring the final resolved path remains confined to the intended target folder.
5. **Preconditions and impact:** No authentication is required. An attacker can extract arbitrary files from the host filesystem that the application process has permission to read (such as `/etc/passwd` or the application source code). This results in a total loss of confidentiality.
6. **Proposed test:** Send an unauthenticated GET request to `/files?path=../app.py` or `/files?path=../../../../../etc/passwd` and observe whether the server returns the contents of those files instead of a standard material file.
7. **Assumptions, uncertainty, and confidence:** High confidence. This relies on the code fact that `pathlib` concatenates the `..` segments and `send_file` relies on the operating system to resolve them. It is assumed the underlying OS permits traversal via relative directory segments.

#### 2. VULN-02: Broken Object Level Authorization

1. **Identifier and title:** VULN-02 Broken Object Level Authorization
2. **Location:** `app.py`, `get_profile` and `get_grades` functions, lines 75-86.
3. **Attacker-controlled input:** The `student_id` variable passed as a URL path parameter in `/students/<student_id>/profile` and `/grades/<student_id>`.
4. **Missing control and root cause:** Missing authentication enforcement and missing ownership verification. The root cause is exposing data retrieval endpoints without checking if the requester possesses a valid session or has the logical authorization to view the requested identifier.
5. **Preconditions and impact:** No preconditions exist. An attacker can systematically iterate through integer values for `student_id` to scrape all student profiles and academic records.
6. **Proposed test:** Send unauthenticated GET requests to `/students/1001/profile` and `/grades/1002` from a clean HTTP client to confirm the application freely returns sensitive profile and grade data.
7. **Assumptions, uncertainty, and confidence:** High confidence. Code facts show zero session validation in these routes. It is inferred from the application context that grades and personal profiles are sensitive data restricted to the specific student, assigned professors or administrators.

#### 3. VULN-03: Unauthenticated Grade Modification

1. **Identifier and title:** VULN-03 Unauthenticated Grade Modification
2. **Location:** `app.py`, `update_grade` function, lines 88-102.
3. **Attacker-controlled input:** The JSON payload processed by `flask.request.get_json()`, specifically the `student_id`, `course_id` and `grade` fields.
4. **Missing control and root cause:** Missing access control and privilege validation. The root cause is deploying a state-changing administrative endpoint without any perimeter defense to verify the identity and role of the client making the request.
5. **Preconditions and impact:** No preconditions. Any individual capable of reaching the API can freely alter existing grades or append fraudulent ones. This destroys the data integrity of the academic system.
6. **Proposed test:** Send an unauthenticated POST request to `/grades/update` containing a JSON payload that modifies a known grade. Subsequently fetch the grades to verify the fraudulent update was applied.
7. **Assumptions, uncertainty, and confidence:** High confidence. The code definitively lacks session checks here. The business policy inference is that students and anonymous entities should never hold the permissions required to modify official academic grades.

#### 4. VULN-04: Insecure Storage of Secrets and Credentials

1. **Identifier and title:** VULN-04 Insecure Storage of Secrets and Credentials
2. **Location:** `app.py`, global scope, line 7 (`SECRET_KEY`) and lines 24-34 (`USERS` dictionary).
3. **Attacker-controlled input:** Not directly exploitable via input flow but intrinsically linked to the authentication checks in the `/login` endpoint.
4. **Missing control and root cause:** Missing cryptographic hashing for passwords and missing externalized secrets management. The root cause is hardcoding sensitive configuration and plaintext credentials directly into the source file.
5. **Preconditions and impact:** An attacker must first obtain the source code (which is trivial if VULN-01 is exploited). The attacker can then forge valid session cookies using the static secret key or authenticate directly as any user using the plaintext passwords.
6. **Proposed test:** Review the source file to confirm the presence of the static `SECRET_KEY` and plaintext passwords. A secondary test involves forging a Flask session cookie using the exposed secret key to hijack an administrative session.
7. **Assumptions, uncertainty, and confidence:** High confidence. While the context states this is a simplified teaching environment, deploying this paradigm exposes fatal systemic weaknesses that violate fundamental security engineering principles.

#### 5. VULN-05: Information Disclosure in Error Handler

1. **Identifier and title:** VULN-05 Information Disclosure in Error Handler
2. **Location:** `app.py`, `handle_error` function, lines 110-114.
3. **Attacker-controlled input:** Any malformed input that provokes an unhandled exception during route execution (for example, providing non-integer data where an integer is expected).
4. **Missing control and root cause:** Missing sanitization of outbound error messages. The root cause is catching generic exceptions and returning their raw internal string representations directly to the end user.
5. **Preconditions and impact:** The attacker must successfully trigger an application error. Doing so may leak underlying file paths, infrastructure details or logic implementation quirks that assist the attacker in mapping the attack surface.
6. **Proposed test:** Send a POST request to `/grades/update` containing a deliberately malformed JSON payload (such as missing required keys) and analyze the HTTP 500 response body for leaked internal variable names or Python exceptions.
7. **Assumptions, uncertainty, and confidence:** Moderate confidence regarding severity. It is assumed the overarching security policy strictly forbids exposing raw software architecture details to arbitrary external clients.
