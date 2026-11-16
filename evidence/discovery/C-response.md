### Findings Table

| ID | Title | Affected Functions | Violated Policy |
| --- | --- | --- | --- |
| **F1** | Missing Authentication on Protected Endpoints | `get_profile`, `get_grades`, `update_grade`, `download_file` | R1 |
| **F2** | Broken Access Control on Profiles and Grades | `get_profile`, `get_grades`, `update_grade` | R2, R3, R4 |
| **F3** | Path Traversal in File Download | `download_file` | R6 |
| **F4** | Insufficient Input Validation on Grade Updates | `update_grade` | R5 |
| **F5** | Information Exposure via Global Error Handler | `handle_error` | R7 |

---

### Finding Details

**F1: Missing Authentication on Protected Endpoints**

1. **Identifier and Title:** F1 Missing Authentication on Protected Endpoints
2. **Location:** `app.py` in `get_profile` (line 76), `get_grades` (line 82), `update_grade` (line 87) and `download_file` (line 103).
3. **Attacker-controlled Input / Execution Path:** An attacker sends direct HTTP GET or POST requests to the affected endpoints without submitting a prior login request or providing a valid session cookie.
4. **Root Cause:** The application explicitly sets session variables in `/login` but fails to check for the presence of a valid `flask.session` before executing the logic in the protected routes. This violates the R1 requirement that restricts these actions to authenticated users.
5. **Preconditions and Impact:** Any user with network access to the API can reach these endpoints. The impact is severe as it enables completely anonymous access to sensitive academic records and internal teaching materials.
6. **Proposed Test:** Send a `GET /students/1001/profile` request with an empty cookie jar. Assert that the server returns a `401 Unauthorized` status code rather than a `200 OK`.
7. **Assumptions and Confidence:** High confidence. The code demonstrated lacks any decorators or procedural checks to enforce session validity on these specific functions.

**F2: Broken Access Control on Profiles and Grades**

1. **Identifier and Title:** F2 Broken Access Control on Profiles and Grades
2. **Location:** `app.py` in `get_profile` (line 76), `get_grades` (line 82) and `update_grade` (line 87).
3. **Attacker-controlled Input / Execution Path:** An authenticated user modifies the `student_id` in the URL path parameters or alters the `student_id` and `course_id` fields within a JSON payload sent to the update endpoint.
4. **Root Cause:** The endpoints fail to evaluate the authorization context of the requester. They do not compare the target `student_id` or `course_id` against the `student_id`, `role` or `courses` stored in `flask.session`. This violates R2, R3 and R4 by failing to enforce privacy boundaries and role-based restrictions.
5. **Preconditions and Impact:** An attacker must be authenticated (assuming F1 is resolved). A student could view or alter grades belonging to peers. A professor could modify grades for courses they do not teach. This compromises data confidentiality and integrity.
6. **Proposed Test:** Authenticate as a student (e.g. Alice) and submit a `GET /students/1002/profile` request (Bob's profile). Assert that the server returns a `403 Forbidden` status.
7. **Assumptions and Confidence:** High confidence. The code facts show direct database lookups using solely the user-supplied identifiers without any authorization validation checks.

**F3: Path Traversal in File Download**

1. **Identifier and Title:** F3 Path Traversal in File Download
2. **Location:** `app.py` in `download_file` (line 103).
3. **Attacker-controlled Input / Execution Path:** A user supplies a manipulated string containing directory traversal characters (such as `../`) to the `path` query parameter. This is passed to `MATERIALS_DIR / raw_path` and handed directly to `flask.send_file()`.
4. **Root Cause:** The application relies on naive path concatenation without verifying if the resolved absolute path remains contained within the `MATERIALS_DIR` boundary. This violates R6.
5. **Preconditions and Impact:** A user must have network access (and authentication if F1 is patched). The attacker can escape the intended directory to read arbitrary files on the server file system (such as source code or environment files) leading to complete application compromise.
6. **Proposed Test:** Send a `GET /files?path=../app.py` request. Assert that the application rejects the request and does not return the application source code.
7. **Assumptions and Confidence:** High confidence. The Python `pathlib` module does not automatically sandbox paths when initialized with `../` strings and `send_file` will process the traversed path.

**F4: Insufficient Input Validation on Grade Updates**

1. **Identifier and Title:** F4 Insufficient Input Validation on Grade Updates
2. **Location:** `app.py` in `update_grade` (line 87).
3. **Attacker-controlled Input / Execution Path:** A user submits a JSON payload to `POST /grades/update` containing missing keys, boolean values, out-of-bounds integers or invalid course identifiers. The dictionary accesses these keys blindly and writes them to the in-memory array.
4. **Root Cause:** The function lacks structural and semantic validation of the incoming data payload. It fails to verify data types, value boundaries (0 to 20) and course allowlists before appending or updating the internal `GRADES` list. This violates R5.
5. **Preconditions and Impact:** The attacker needs the ability to send POST requests to the endpoint. Malformed inputs can corrupt the application state, disrupt downstream processing or trigger unhandled server errors (such as `KeyError` when required fields are omitted).
6. **Proposed Test:** Submit a `POST /grades/update` request with the payload `{"student_id": 1001, "course_id": "UNKNOWN", "grade": 25}`. Assert that the response is a client error (e.g. 400) and the internal data remains unchanged.
7. **Assumptions and Confidence:** High confidence. The code directly extracts and assigns JSON values without any preceding conditional validation logic.

**F5: Information Exposure via Global Error Handler**

1. **Identifier and Title:** F5 Information Exposure via Global Error Handler
2. **Location:** `app.py` in `handle_error` (line 108).
3. **Attacker-controlled Input / Execution Path:** A user deliberately sends a malformed request (such as providing a string "abc" where an integer `student_id` is expected) to trigger a `ValueError` in `int(student_id)`. The exception propagates to the `@app.errorhandler` and its string representation is serialized into the HTTP response.
4. **Root Cause:** The global error handler captures all unhandled exceptions and explicitly reflects the exception class name and internal error string back to the client. This violates R7 which mandates proper client errors without exposing internal exception details.
5. **Preconditions and Impact:** An attacker merely needs to trigger a standard Python exception via malformed input. The exposure of stack details or system state greatly assists attackers in understanding the internal application logic and crafting more targeted exploits.
6. **Proposed Test:** Send a `GET /students/invalid_string/profile` request. Assert that the response does not contain `ValueError` or the literal Python error message in the JSON body.
7. **Assumptions and Confidence:** High confidence. The code explicitly returns `str(exc)` in a 500 status payload.
