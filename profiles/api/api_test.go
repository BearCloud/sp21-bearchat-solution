package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/suite"
)

// TESTS

func TestMain(m *testing.M) {
	// Makes it so any log statements are discarded. Comment these two lines
	// if you want to see the logs.
	log.SetFlags(0)
	log.SetOutput(io.Discard)

	// Runs the tests to completion then exits.
	os.Exit(m.Run())
}

// Runs every test for getProfile()
func TestGetProfile(t *testing.T) {
	suite.Run(t, new(GetProfileTestSuite))
}

// Runs every test for updateProfile()
func TestUpdateProfile(t *testing.T) {
	suite.Run(t, new(UpdateProfileTestSuite))
}

// Tests that getProfile() succeeds in retrieving a Profile that exists.
func (s *GetProfileTestSuite) TestBasicGet() {
	// Insert a fake profile into the users database.
	_, err := s.db.Exec("INSERT INTO users VALUES (?, ?, ?, ?)", s.testProfile.Firstname, s.testProfile.Lastname, s.testProfile.Email, s.testProfile.UUID)
	s.Require().NoError(err, "could not insert user into database")

	rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/profile/"+s.testProfile.UUID, nil)
	r = mux.SetURLVars(r, map[string]string{"uuid": s.testProfile.UUID})

	getProfile(s.db)(rr, r)

	if s.Assert().Equal(http.StatusOK, rr.Result().StatusCode, "incorrect status code returned") {
		var p Profile
		json.NewDecoder(rr.Result().Body).Decode(&p)
		s.Assert().Equal(s.testProfile, p, "incorrect profile returned")
	}

}

// Tests that getProfile() returns an http.StatusBadRequest in the event we ask
// for a profile that doesn't exist.
func (s *GetProfileTestSuite) TestNoExistingUUID() {
	rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/profile/aaaaaa", nil)
	r = mux.SetURLVars(r, map[string]string{"uuid": "aaaaaa"})

	getProfile(s.db)(rr, r)

	s.Assert().Equal(http.StatusBadRequest, rr.Result().StatusCode, "incorrect status code returned")
}

// Performs a basic test that updates the profile.
func (s *UpdateProfileTestSuite) TestUpdateProfile() {
	// Changes getUUID to a function that records that it's been called.
	// Please call getUUID in updateProfile instead of checking the cookie manually :^).
	var getUUIDCalled bool
	getUUID = func(w http.ResponseWriter, r *http.Request) (uuid string, err error) {
		getUUIDCalled = true
		return s.testProfile.UUID, nil
	}

	rr, r := s.generateRequestAndResponse(http.MethodPut, "/api/profile/"+s.testProfile.UUID, bytes.NewBuffer(s.profileJSON(s.testProfile)))
	r = mux.SetURLVars(r, map[string]string{"uuid": s.testProfile.UUID})

	updateProfile(s.db)(rr, r)

	if s.Assert().Equal(http.StatusOK, rr.Result().StatusCode, "incorrect status code returned") {
		s.Assert().True(getUUIDCalled, "getUUID() not called in updateProfile()")
		s.Assert().True(s.verifyProfileExists(s.testProfile), "could not find profile")
	}
}

// Makes sure updateProfile() errors with http.StatusUnauthorized if someone tries to
// update a profile that isn't theirs.
func (s *UpdateProfileTestSuite) TestMatchingUUID() {
	// This line ensures that no matter what the UUID is, we will get one that isn't the same.
	rr, r := s.generateRequestAndResponse(http.MethodPut, "/api/profile/"+s.testProfile.UUID+"1", bytes.NewBuffer(s.profileJSON(s.testProfile)))
	r = mux.SetURLVars(r, map[string]string{"uuid": s.testProfile.UUID + "1"})

	var getUUIDCalled bool
	getUUID = func(w http.ResponseWriter, r *http.Request) (uuid string, err error) {
		getUUIDCalled = true
		return s.testProfile.UUID, nil
	}

	updateProfile(s.db)(rr, r)

	s.Assert().Equal(http.StatusUnauthorized, rr.Result().StatusCode, "incorrect status code returned")
	s.Assert().True(getUUIDCalled, "getUUID() function not called")
	s.Assert().False(s.verifyProfileExists(s.testProfile), "profile was added to the database by wrong user")
}

// HELPER METHODS AND DEFINITIONS

// Defines a test suite for the entire profiles microservice.
type ProfilesTestSuite struct {
	suite.Suite

	// A connection to the sql database.
	db *sql.DB

	// A test profile that contains fake information.
	testProfile Profile

	// Stored the original reference to getUUID so it can be restored after tests.
	getUUID func(w http.ResponseWriter, r *http.Request) (uuid string, err error)
}

// Defines a test suite for getProfile().
type GetProfileTestSuite struct {
	ProfilesTestSuite
}

// Defines a test suite for updateProfile().
type UpdateProfileTestSuite struct {
	ProfilesTestSuite
}

// Clears the users database so the tests remain independent.
func (s *ProfilesTestSuite) clearDatabase() (err error) {
	_, err = s.db.Exec("TRUNCATE TABLE users")
	return err
}

// Returns a byte array with a JSON containing the passed in Profile. Useful for making basic requests.
func (s *ProfilesTestSuite) profileJSON(p Profile) []byte {
	testProfileJSON, err := json.Marshal(p)

	// Makes sure the error returned here is nil.
	s.Require().NoErrorf(err, "failed to initialize test profile %s", err)

	return testProfileJSON
}

// Setup the db variable before any tests are run.
func (s *ProfilesTestSuite) SetupSuite() {
	// Connects to the MySQL Docker Container. Notice that we use localhost
	// instead of the container's IP address since it is assumed these
	// tests run outside of the container network.
	db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/profiles")
	s.Require().NoError(err, "could not connect to the database!")
	s.db = db
	s.testProfile = Profile{
		"Dev",
		"Ops",
		"dab@berkeley.edu",
		"1", // Yes we're number 1
	}
	// Save the getUUID function so it can be restored.
	s.getUUID = getUUID
}

// Makes sure the database starts in a clean state before each test.
func (s *ProfilesTestSuite) SetupTest() {
	err := s.db.Ping()
	if err != nil {
		s.T().Logf("could not connect to database. skipping test. %s", err)
		s.T().SkipNow()
	}

	err = s.clearDatabase()
	if err != nil {
		s.T().Logf("could not clear database. skipping test. %s", err)
		s.T().SkipNow()
	}

	// Restore the original reference to getUUID so tests can use it if they want.
	getUUID = s.getUUID
}

// Given an HTTP method, API endpoint, and io.Reader, returns a ResponseRecorder and a fake Request
// that can be used for that endpoint. Makes the test fail with an error if any errors are
// encountered.
func (s *ProfilesTestSuite) generateRequestAndResponse(method, endpoint string, body io.Reader) (rr *httptest.ResponseRecorder, r *http.Request) {
	rr = httptest.NewRecorder()
	r, err := http.NewRequest(method, endpoint, body)
	s.Require().NoError(err, "could not initialize fake request and response")
	return rr, r
}

// Given a Profile, checks the profiles database to ensure it exists. Fails the current test if any error occurs while
// querying the databse.
func (s *ProfilesTestSuite) verifyProfileExists(p Profile) bool {
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT * FROM users WHERE firstName=? AND lastName=? AND email=? AND uuid=?)", p.Firstname, p.Lastname, p.Email, p.UUID).Scan(&exists)
	if s.Assert().NoError(err, "failed to query the sql database for the profile") {
		return exists
	}
	return false
}
