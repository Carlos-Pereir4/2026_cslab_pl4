Here is the analysis and the patch to resolve the vulnerabilities in the `/grades/update` endpoint.

### Root Cause Analysis

The `/grades/update` endpoint was completely unprotected and lacked input validation. It blindly trusted the incoming JSON payload and directly applied the updates to the `GRADES` data store.

1. **Missing Authentication & Authorization:** It did not check `flask.session` to verify if the requester was logged in, nor did it verify if the user had the correct role (Admin or Professor assigned to the specific course).
2. **Insufficient Input Validation:** It did not verify the presence or types of the required fields, nor did it check if the grade was within the valid 0-20 bounds or if the `student_id` or `course_id` actually existed. Because Python treats `bool` as a subclass of `int` (`True == 1`), `isinstance(grade, int)` checks can inadvertently allow booleans if strictly checking types isn't done properly.

### Unified Diff

```diff
--- app.py
+++ app.py
@@ -107,14 +107,43 @@
 
 @app.post("/grades/update")
 def update_grade():
-    data = flask.request.get_json()
-
-    student_id = data["student_id"]
-    course_id = data["course_id"]
-    grade = data["grade"]
-
+    # 1. Authentication
+    if "user" not in flask.session:
+        return {"error": "unauthenticated"}, 401
+        
+    # 2. Extract Data
+    data = flask.request.get_json(silent=True)
+    if not data:
+        return {"error": "invalid json"}, 400
+        
+    student_id = data.get("student_id")
+    course_id = data.get("course_id")
+    grade = data.get("grade")
+
+    # 3. Input Validation: Missing fields
+    if student_id is None or course_id is None or grade is None:
+        return {"error": "missing fields"}, 400
+
+    # 4. Input Validation: Constraints & Types
+    if course_id not in ["SRS", "SSD"]:
+        return {"error": "invalid course"}, 400
+        
+    if student_id not in STUDENT_PROFILES:
+        return {"error": "invalid student"}, 400
+
+    if type(grade) is bool or not isinstance(grade, (int, float)):
+        return {"error": "invalid grade type"}, 400
+        
+    if not (0 <= grade <= 20):
+        return {"error": "invalid grade value"}, 400
+
+    # 5. Authorization
+    role = flask.session.get("role")
+    if role not in ["admin", "professor"] or (role == "professor" and course_id not in flask.session.get("courses", [])):
+        return {"error": "forbidden"}, 403
+
     row = find_grade(student_id, course_id)
     if row is None:
         GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
     else:
         row["grade"] = grade

```

### Control Explanation

1. **Authentication:** The endpoint now checks for the presence of `"user"` in `flask.session`. If absent, it immediately rejects the request with a `401 Unauthorized`.
2. **Authorization:** After extracting `course_id`, the endpoint validates the user's role. Students are implicitly denied. Professors are only authorized if the target `course_id` is present in their session's `courses` list. Admins are permitted natively. Failures result in `403 Forbidden`.
3. **Input Validation:**
* Validates that all required fields (`student_id`, `course_id`, `grade`) exist (R5).
* Validates `course_id` against the strictly known set of courses ("SRS", "SSD").
* Validates `student_id` by ensuring the ID is an existing key in `STUDENT_PROFILES`.
* Explicitly checks for boolean abuse using `type(grade) is bool`. It verifies that the value is genuinely an `int` or `float`, and enforces the inclusive bounds check (`0 <= grade <= 20`).



### Assumptions and Limitations

* **Hardcoded Course Validation:** The list of valid courses (`["SRS", "SSD"]`) is hardcoded. In a real-world scenario, this should be queried dynamically against a `COURSES` database table or constant.
* **Concurrent Modifications / Race Conditions:** We are operating on an in-memory `list` and `dict` without thread locks. In a production environment with a real database, database constraints (like foreign keys) and transactions should be used to guarantee atomicity and relational integrity.
* **JSON Exception Handling:** Adding `silent=True` to `get_json()` prevents Flask from automatically throwing a 400 HTML response if the payload isn't valid JSON, allowing the application to return a predictable JSON `400 Bad Request` instead.

### Suggested Regression Tests

To ensure these rules remain enforced in the future, these tests should be added to your test suite:

```python
def test_unauthenticated_grade_update(client):
    """Ensure anonymous users cannot update grades."""
    response = client.post("/grades/update", json={"student_id": 1001, "course_id": "SRS", "grade": 15})
    assert response.status_code == 401

def test_unauthorized_professor_grade_update(client):
    """Ensure a professor cannot update a grade for a course they do not teach."""
    login(client, "prof_srs", "profpw")
    response = client.post("/grades/update", json={"student_id": 1001, "course_id": "SSD", "grade": 15})
    assert response.status_code == 403

def test_student_forbidden_grade_update(client):
    """Ensure students cannot update their own grades."""
    login(client, "alice", "alicepw")
    response = client.post("/grades/update", json={"student_id": 1001, "course_id": "SRS", "grade": 20})
    assert response.status_code == 403

def test_missing_fields_grade_update(client):
    """Ensure the API rejects payloads missing required fields."""
    login(client, "prof_srs", "profpw")
    response = client.post("/grades/update", json={"student_id": 1001})
    assert response.status_code == 400

def test_invalid_student_id_update(client):
    """Ensure grades cannot be assigned to non-existent students."""
    login(client, "prof_srs", "profpw")
    response = client.post("/grades/update", json={"student_id": 9999, "course_id": "SRS", "grade": 15})
    assert response.status_code == 400

```