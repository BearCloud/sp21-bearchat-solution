package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
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

// Runs every test that uses the database.
func TestAll(t *testing.T) {
	suite.Run(t, new(ProfilesTestSuite))
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
}

// Contains the tests for signing up to Bearchat.
func (s *ProfilesTestSuite) TestGetProfile() {
	// This test actually makes use of the real MySQL database. This means you need to start it
	// for this test to work.

	// Test if UUID exists in database
	s.Run("Test No Existing UUID", func() {
		s.SetupTest()
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Call the function with our fake stuff.
		signup(m, s.db)(rr, r)

		// Make sure the database has an entry for our new user.
		s.checkExists(s.testCreds.Username, s.testCreds.Email)

		// Check that the user was given an access_token and a refresh_token.
		s.verifyLoginCookies(rr.Result().Cookies())

		// Lastly, make sure that the mailer was called to send an email.
		s.Assert().True(m.sendEmailCalled, "code did not call SendEmail with mailer")

		// Let user sign in.
		r = httptest.NewRequest(http.MethodPost, "/api/auth/signin", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr = httptest.NewRecorder()
		signin(s.db)(rr, r)

		// Check that the user was given an access_token and a refresh_token.
		s.verifyLoginCookies(rr.Result().Cookies())

		// Get user profile with fake UUID
		r = httptest.NewRequest(http.MethodGet, "/api/profile/aaaaaa", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr = httptest.NewRecorder()
		getProfile(rr, r)

		//Check correct status returned.
		s.Assert().Equal(http.StatusBadRequest, rr.Result().StatusCode, "incorrect status code returned")
	})
}

func (s *ProfilesTestSuite) TestUpdateProfile() {
	// Check if profile is correctly updated
	s.Run("Test Update Profile", func() {
		s.SetupTest()
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Call the function with our fake stuff.
		signup(m, s.db)(rr, r)

		// Make sure the database has an entry for our new user.
		s.checkExists(s.testCreds.Username, s.testCreds.Email)

		// Check that the user was given an access_token and a refresh_token.
		s.verifyLoginCookies(rr.Result().Cookies())

		// Lastly, make sure that the mailer was called to send an email.
		s.Assert().True(m.sendEmailCalled, "code did not call SendEmail with mailer")

		// Let user sign in.
		r = httptest.NewRequest(http.MethodPost, "/api/auth/signin", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr = httptest.NewRecorder()
		signin(s.db)(rr, r)

		// Check that the user was given an access_token and a refresh_token.
		s.verifyLoginCookies(rr.Result().Cookies())

		// Write user profile
		r = httptest.NewRequest(http.MethodGet, "/api/profile/{uuid}", bytes.NewBuffer(s.testProfile))
		rr = httptest.NewRecorder()
		updateProfile(rr, r)

		// Make sure profile was updated
		err := s.db_profiles.QueryRow("SELECT firstName FROM users WHERE firstName=?", s.testProfile.firstName)
		if err == sql.ErrNoRows {
			s.Assert().NoError(err, "some properties of a profile were not updated correctly")
		}
		err = s.db_profiles.QueryRow("SELECT lastName FROM users WHERE lastName=?", s.testProfile.lastName)
		if err == sql.ErrNoRows {
			s.Assert().NoError(err, "some properties of a profile were not updated correctly")
		}
		err = s.db_profiles.QueryRow("SELECT email FROM users WHERE email=?", s.testProfile.email)
		if err == sql.ErrNoRows {
			s.Assert().NoError(err, "some properties of a profile were not updated correctly")
		}
	})

	// Check if UUID from cookies matches url UUID
	s.Run("Test Matching UUID", func() {
		s.SetupTest()
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Call the function with our fake stuff.
		signup(m, s.db)(rr, r)

		// Make sure the database has an entry for our new user.
		s.checkExists(s.testCreds.Username, s.testCreds.Email)

		// Check that the user was given an access_token and a refresh_token.
		s.verifyLoginCookies(rr.Result().Cookies())

		// Lastly, make sure that the mailer was called to send an email.
		s.Assert().True(m.sendEmailCalled, "code did not call SendEmail with mailer")

		// Let user sign in.
		r = httptest.NewRequest(http.MethodPost, "/api/auth/signin", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr = httptest.NewRecorder()
		signin(s.db)(rr, r)

		// Check that the user was given an access_token and a refresh_token.
		s.verifyLoginCookies(rr.Result().Cookies())

		// Write user profile with fake UUID
		r = httptest.NewRequest(http.MethodGet, "/api/profile/aaaaa", bytes.NewBuffer(s.testProfile))
		rr = httptest.NewRecorder()
		updateProfile(rr, r)

		//Check correct status returned.
		s.Assert().Equal(http.StatusUnauthorized, rr.Result().StatusCode, "incorrect status code returned")
	})
}

// HELPER METHODS AND DEFINITIONS

// Makes a Suite for all of the auth-service tests to live in
type ProfilesTestSuite struct {
	suite.Suite
	db        *sql.DB
	db_profiles *sql.DB
	testCreds Credentials
	testProfile Profile
}

// Clears the users database so the tests remain independent.
func (s *ProfilesTestSuite) clearDatabase() (err error) {
	_, err = s.db.Exec("TRUNCATE TABLE users")
	return err
}

// Returns true iff the cookie matches the expectations for signing up and signing in.
func (s *ProfilesTestSuite) verifyCookie(c *http.Cookie) bool {
	return (c.Name == "access_token" || c.Name == "refresh_token") &&
		c.Expires.After(time.Now()) &&
		c.Path == "/"
}

// Verify that the cookies array contains an access_token and a refresh_token
// with the correct attributes
func (s *ProfilesTestSuite) verifyLoginCookies(cookies []*http.Cookie) {
	if s.Assert().Equal(2, len(cookies), "the wrong amount of cookies were given back") {
		s.Assert().True(s.verifyCookie(cookies[0]), "first cookie does not have proper attributes")
		s.Assert().True(s.verifyCookie(cookies[1]), "second cookie does not have proper attributes")
		s.Assert().NotEqual(cookies[0].Name, cookies[1].Name, "two of the same cookie found")
	}
}

// Returns a byte array with a JSON containing the passed in Credentials. Useful for making basic requests.
func (s *ProfilesTestSuite) credsJSON(c Credentials) []byte {
	testCredsJSON, err := json.Marshal(c)

	// Makes sure the error returned here is nil.
	s.Require().NoErrorf(err, "failed to initialize test credentials %s", err)

	return testCredsJSON
}

// Returns a byte array with a JSON containing the passed in Profile. Useful for making basic requests.
func (s *ProfilesTestSuite) profileJSON(p Profile) []byte {
	testProfileJSON, err := json.Marshal(p)

	// Makes sure the error returned here is nil.
	s.Require().NoErrorf(err, "failed to initialize test profile %s", err)

	return testProfileJSON
}

// Verifies that a user with the passed in email and username is in the database.
func (s *ProfilesTestSuite) checkExists(username, email string) {
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT * FROM users WHERE email=? AND username=?)", email, username).Scan(&exists)
	if s.Assert().NoError(err, "an error occurred while checking the database") {
		s.Assert().True(exists, "could not find the user in the database after signing up")
	}
}

// Setup the db variable before any tests are run.
func (s *ProfilesTestSuite) SetupSuite() {
	// Connects to the MySQL Docker Container. Notice that we use localhost
	// instead of the container's IP address since it is assumed these
	// tests run outside of the container network.
	db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/auth")
	s.Require().NoError(err, "could not connect to the database!")
	db_profiles, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/profiles")
	s.Require().NoError(err, "could not connect to the database!")
	s.db = db
	s.db_profiles = db_profiles
	s.testCreds = Credentials{
		Username: "GoldenBear321",
		Email:    "devops@berkeley.edu",
		Password: "DaddyDenero123",
	}
	s.testProfile = Profile{
		Firstname: "John",
		Lastname: "Denero",
		Email: "dab@berkeley.edu",
	}
}

// Creates a Mailer that only records if SendEmail was called and does nothing else.
type recordMailer struct {
	sendEmailCalled bool
}

func newRecordMailer() *recordMailer {
	return &recordMailer{sendEmailCalled: false}
}

func (m *recordMailer) SendEmail(recipient string, subject string, templatePath string, data map[string]interface{}) error {
	m.sendEmailCalled = true
	return nil
}
