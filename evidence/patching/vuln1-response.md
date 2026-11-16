Here is a minimal, reviewable patch that resolves the Broken Object Level Authorization (BOLA) vulnerability while respecting the access policies.

### Explanation of the Control

The vulnerability occurs because the API relies solely on the client-provided `student_id` parameter to look up profiles and grades, without validating if the current session possesses the rights to access that record.

To fix this, we enforce authorization directly at the resource level:

1. **Authentication Check (R1, R7):** We verify that `"user"` is present in the session. If not, we return a `401 Unauthorized`.
2. **Object-Level Authorization Check (R2, R3, R7):** We evaluate the `role` from the session. Administrators are granted blanket access to profiles and grades. For students, we ensure that the requested `student_id` exactly matches the `student_id` bound to their session. Professors and other roles, or mismatched students, receive a `403 Forbidden`.

I have applied the exact same control to the `/grades/<student_id>` endpoint since grades are under the identical ownership and role policy (R2, R3).

### Unified Diff

```diff
--- app.py
+++ app.py
@@ -107,13 +107,25 @@
 
 @app.get("/students/<student_id>/profile")
 def get_profile(student_id):
+    if "user" not in flask.session:
+        return {"error": "unauthenticated"}, 401
+    role = flask.session.get("role")
+    if role != "admin" and (role != "student" or str(flask.session.get("student_id")) != str(student_id)):
+        return {"error": "forbidden"}, 403
+
     profile = STUDENT_PROFILES.get(int(student_id))
     if profile is None:
         return {"error": "student not found"}, 404
     return flask.jsonify(profile)
 
 @app.get("/grades/<student_id>")
 def get_grades(student_id):
+    if "user" not in flask.session:
+        return {"error": "unauthenticated"}, 401
+    role = flask.session.get("role")
+    if role != "admin" and (role != "student" or str(flask.session.get("student_id")) != str(student_id)):
+        return {"error": "forbidden"}, 403
+
     sid = int(student_id)
     rows = [row for row in GRADES if row["student_id"] == sid]
     return flask.jsonify(rows)

```

### Remaining Assumptions or Limitations

* **Integer/String Conversions:** The check relies on comparing `str(student_id)`, which assumes `flask.session.get("student_id")` behaves consistently (doesn't become `None` unless the user is completely unlinked to a student, in which case `"None" != student_id` appropriately fails safe).
* **Professors Grading Access:** The prompt limits professor access to profiles (`R3`), but does not strictly specify if professors should be allowed to *read grades* of their enrolled students in `/grades/<student_id>`. As patched, professors are blocked from `get_grades` entirely, which aligns with standard restrictive setups unless they have explicit permission overrides.
* **Other Endpoints Unpatched:** This patch solely focuses on read-access to `student_id` parameters. Endpoints like `POST /grades/update` and `GET /files` are currently unpatched and suffer from separate authorization or injection issues (BOLA/CSRF and Path Traversal, respectively).

### Suggested Additional Regression Tests

1. **Unauthenticated access:** Ensure `GET /students/1001/profile` returns `401 Unauthorized` without a session.
2. **Student Grade Access:** Verify that Alice (student) gets `403 Forbidden` if she calls `GET /grades/1002`, but gets `200 OK` on `GET /grades/1001`.
3. **Admin Verification:** Verify that `admin1` (admin) gets `200 OK` when querying both `GET /students/1001/profile` and `GET /grades/1002`.