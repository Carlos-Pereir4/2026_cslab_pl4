We are now repairing a confirmed vulnerability in the supplied application.
Confirmed finding:
Insufficient Input Validation and Missing Authorization on Grade Updates. The /grades/update endpoint accepts malformed data (booleans, out-of-bounds integers) and does not verify if the user is authenticated or authorized (e.g., an assigned professor or admin) to update the grade.
Required behavior:
R1 — Authentication: Grade updates require an authenticated user.
R3 — Academic staff scope: Professors may update grades only for their assigned courses. Administrators may update grades.
R4 — Complete authorization: Check authorization on every relevant request.
R5 — Input validation: Grade updates require a JSON object with an existing student identifier, a known course identifier, and a numeric grade from 0 to 20 inclusive. Boolean values are not valid grades. Reject missing fields and malformed input without applying an update. Known courses for this baseline are SRS and SSD.
R7 — Error handling: Unauthenticated protected requests return 401; authenticated but unauthorized requests return 403. Invalid requests must return appropriate client errors (e.g., 400). A denied or invalid update must leave stored data unchanged.
Reproduction / CI Failure:

_______________________ test_reject_out_of_bounds_grade ________________________
client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
    def test_reject_out_of_bounds_grade(client):
        """Malicious operation: Professor submits a grade higher than 20."""
        login(client, "prof_srs", "profpw")
        # Alice's original grade for SRS is 14 in the baseline data
        original_grade = 14
        response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "SRS", "grade": 25},
        )
        # Must reject with a client error (e.g., 400 Bad Request)
>       assert response.status_code == 400
E       assert 200 == 400

__________________________ test_reject_boolean_grade ___________________________
client = <FlaskClient <Flask 'baseline_secure_coding_api'>>
    def test_reject_boolean_grade(client):
        """Meaningful variation: Submitting a boolean instead of a number."""
        login(client, "prof_srs", "profpw")
        original_grade = 14
        response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "SRS", "grade": True},
        )
        # Because True == 1 in Python, weak validation will accept it. Must be 400.
>       assert response.status_code == 400
E       assert 200 == 400

Propose a minimal, reviewable patch addressing the root cause. Preserve the API's legitimate functionality and relevant response contracts. Do not delete endpoints, disable features, weaken tests, or suppress scanner rules to hide the issue. Identify all affected paths that need the same control. Return a unified diff, explain the control being implemented, and identify remaining assumptions or limitations. Suggest additional regression tests.

import dataclasses
import pathlib
import typing

import flask

app = flask.Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key"

# -----------------------------------------------------------------------------
# Intentionally small in-memory "database"
# -----------------------------------------------------------------------------

BASE_DIR = pathlib.Path(__file__).resolve().parent
MATERIALS_DIR = BASE_DIR / "materials"
MATERIALS_DIR.mkdir(exist_ok=True)

# Seed a couple of demo files.
(MATERIALS_DIR / "srs-summary.txt").write_text(
    "Secure Requirements Engineering summary", encoding="utf-8"
)
(MATERIALS_DIR / "secure-coding.txt").write_text(
    "Secure coding practices notes", encoding="utf-8"
)


@dataclasses.dataclass
class User:
    username: str
    password: str
    role: str
    student_id: typing.Optional[int] = None
    courses: typing.Optional[list[str]] = None


USERS = {
    "alice": User(username="alice", password="alicepw", role="student", student_id=1001),
    "bob": User(username="bob", password="bobpw", role="student", student_id=1002),
    "prof_srs": User(
        username="prof_srs", password="profpw", role="professor", courses=["SRS"]
    ),
    "admin1": User(username="admin1", password="adminpw", role="admin"),
}

STUDENT_PROFILES = {
    1001: {"student_id": 1001, "name": "Alice", "email": "alice@uc.pt", "program": "MEI"},
    1002: {"student_id": 1002, "name": "Bob", "email": "bob@uc.pt", "program": "MEI"},
}

GRADES = [
    {"student_id": 1001, "course_id": "SRS", "grade": 14},
    {"student_id": 1002, "course_id": "SRS", "grade": 15},
    {"student_id": 1001, "course_id": "SSD", "grade": 16},
]

def find_grade(student_id, course_id):
    for row in GRADES:
        if row["student_id"] == student_id and row["course_id"] == course_id:
            return row
    return None


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------

@app.get("/")
def index():
    return {
        "message": "Baseline Secure Coding API",
        "endpoints": [
            "POST /login",
            "POST /logout",
            "GET /me",
            "GET /students/<student_id>/profile",
            "POST /grades/update",
            "GET /grades/<student_id>",
            "GET /files?path=<name>",
        ],
    }

@app.post("/login")
def login():
    username = flask.request.form.get("username", "")
    password = flask.request.form.get("password", "")

    user = USERS.get(username)
    if user is None or user.password != password:
        return {"error": "invalid credentials"}, 401

    flask.session["user"] = user.username
    flask.session["role"] = user.role
    flask.session["student_id"] = user.student_id
    flask.session["courses"] = user.courses or []

    return flask.redirect("/me")

@app.post("/logout")
def logout():
    flask.session.clear()
    return {"status": "logged out"}

@app.get("/me")
def me():
    if "user" not in flask.session:
        return {"user": None}

    return {
        "user": flask.session.get("user"),
        "role": flask.session.get("role"),
        "student_id": flask.session.get("student_id"),
        "courses": flask.session.get("courses"),
    }

@app.get("/students/<student_id>/profile")
def get_profile(student_id):
    if "user" not in flask.session:
       return {"error": "unauthenticated"}, 401
    role = flask.session.get("role")
    if role != "admin" and (role != "student" or str(flask.session.get("student_id")) != str(student_id)):
       return {"error": "forbidden"}, 403
    
    profile = STUDENT_PROFILES.get(int(student_id))
    if profile is None:
        return {"error": "student not found"}, 404
    return flask.jsonify(profile)

@app.get("/grades/<student_id>")
def get_grades(student_id):
    if "user" not in flask.session:
      return {"error": "unauthenticated"}, 401
    role = flask.session.get("role")
    if role != "admin" and (role != "student" or str(flask.session.get("student_id")) != str(student_id)):
       return {"error": "forbidden"}, 403
    
    sid = int(student_id)
    rows = [row for row in GRADES if row["student_id"] == sid]
    return flask.jsonify(rows)

@app.post("/grades/update")
def update_grade():
    data = flask.request.get_json()

    student_id = data["student_id"]
    course_id = data["course_id"]
    grade = data["grade"]

    row = find_grade(student_id, course_id)
    if row is None:
        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
    else:
        row["grade"] = grade

    return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}

@app.get("/files")
def download_file():
    raw_path = flask.request.args.get("path", "")
    target = MATERIALS_DIR / raw_path
    return flask.send_file(target)

@app.errorhandler(Exception)
def handle_error(exc):
    return {
        "error": str(exc),
        "type": exc.__class__.__name__,
    }, 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)