Run python -m pytest -v tests_security
============================= test session starts ==============================
platform linux -- Python 3.10.22, pytest-8.4.2, pluggy-1.7.0 -- /opt/hostedtoolcache/Python/3.10.22/x64/bin/python
cachedir: .pytest_cache
rootdir: /home/runner/work/2026_cslab_pl4/2026_cslab_pl4
collecting ... collected 6 items

tests_security/test_grade_authorization.py::test_student_can_read_own_profile PASSED [ 16%]
tests_security/test_grade_authorization.py::test_student_cannot_read_other_profile FAILED [ 33%]
tests_security/test_grade_authorization.py::test_professor_cannot_read_student_profile FAILED [ 50%]
tests_security/test_grade_authorization.py::test_assigned_professor_can_update_grade PASSED [ 66%]
tests_security/test_grade_authorization.py::test_reject_out_of_bounds_grade FAILED [ 83%]
tests_security/test_grade_authorization.py::test_reject_boolean_grade FAILED [100%]

=================================== FAILURES ===================================
____________________ test_student_cannot_read_other_profile ____________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>

    def test_student_cannot_read_other_profile(client):
        """Malicious operation: Alice attempts to read Bob's profile."""
        login(client, "alice", "alicepw")
        response = client.get("/students/1002/profile")
    
        # Must be denied (403 Forbidden). Currently fails (returns 200) in baseline.
>       assert response.status_code == 403
E       assert 200 == 403
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code

tests_security/test_grade_authorization.py:33: AssertionError
__________________ test_professor_cannot_read_student_profile __________________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>

    def test_professor_cannot_read_student_profile(client):
        """Meaningful variation: Professor attempts to read a student's profile."""
        login(client, "prof_srs", "profpw")
        response = client.get("/students/1001/profile")
    
        # Must be denied per R3. Currently fails (returns 200) in baseline.
>       assert response.status_code == 403
E       assert 200 == 403
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code

tests_security/test_grade_authorization.py:41: AssertionError
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
>       assert response.status_code == 400
E       assert 200 == 400
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code

tests_security/test_grade_authorization.py:71: AssertionError
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
>       assert response.status_code == 400
E       assert 200 == 400
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code

tests_security/test_grade_authorization.py:87: AssertionError
=========================== short test summary info ============================
FAILED tests_security/test_grade_authorization.py::test_student_cannot_read_other_profile - assert 200 == 403
 +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code
FAILED tests_security/test_grade_authorization.py::test_professor_cannot_read_student_profile - assert 200 == 403
 +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code
FAILED tests_security/test_grade_authorization.py::test_reject_out_of_bounds_grade - assert 200 == 400
 +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code
FAILED tests_security/test_grade_authorization.py::test_reject_boolean_grade - assert 200 == 400
 +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code
========================= 4 failed, 2 passed in 0.05s =========================