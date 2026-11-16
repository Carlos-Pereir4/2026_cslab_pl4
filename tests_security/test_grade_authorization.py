import baseline_secure_coding_api as api

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username



# Vulnerability 1: Broken Authorization (BOLA) on Profiles


def test_student_can_read_own_profile(client):
    """Legitimate operation: Alice reads her own profile."""
    login(client, "alice", "alicepw")
    response = client.get("/students/1001/profile")
    assert response.status_code == 200
    assert response.get_json()["name"] == "Alice"

def test_student_cannot_read_other_profile(client):
    """Malicious operation: Alice attempts to read Bob's profile."""
    login(client, "alice", "alicepw")
    response = client.get("/students/1002/profile")
    
    # Must be denied (403 Forbidden). Currently fails (returns 200) in baseline.
    assert response.status_code == 403 

def test_professor_cannot_read_student_profile(client):
    """Meaningful variation: Professor attempts to read a student's profile."""
    login(client, "prof_srs", "profpw")
    response = client.get("/students/1001/profile")
    
    # Must be denied per R3. Currently fails (returns 200) in baseline.
    assert response.status_code == 403



# Vulnerability 2: Insufficient Input Validation on Grade Updates


def test_assigned_professor_can_update_grade(client):
    """Legitimate operation: Professor updates a legitimate grade."""
    login(client, "prof_srs", "profpw")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )
    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18

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
    assert response.status_code == 400
    
    # State preservation check: Assert the grade was NOT altered in the database
    assert api.find_grade(1001, "SRS")["grade"] == original_grade

def test_reject_boolean_grade(client):
    """Meaningful variation: Submitting a boolean instead of a number."""
    login(client, "prof_srs", "profpw")
    original_grade = 14
    
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": True},
    )
    
    # Because True == 1 in Python, weak validation will accept it. Must be 400.
    assert response.status_code == 400
    assert api.find_grade(1001, "SRS")["grade"] == original_grade