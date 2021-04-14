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
	suite.Run(t, new(AuthTestSuite))
}

// Makes sure the database starts in a clean state before each test.
func (s *AuthTestSuite) SetupTest() {
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
func (s *AuthTestSuite) TestSignup() {
	// This test actually makes use of the real MySQL database. This means you need to start it
	// for this test to work.
	s.Run("Test Basic Signup", func() {
		s.SetupTest()
		// Make a fake request and response to probe the function with.
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
	})

	//Test Multiple Signups
	s.Run("Test Multiple Signups", func() {
		s.SetupTest()
		for i := 0; i < 10; i++ {
			// Setup a JSON containing a random user.
			cred := Credentials{Username: strconv.Itoa(i), Email: strconv.Itoa(i), Password: strconv.Itoa(i)}
			credJson := s.credsJSON(cred)

			r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(credJson))
			rr := httptest.NewRecorder()
			m := newRecordMailer()

			// Call the function with our fake stuff.
			signup(m, s.db)(rr, r)

			// Make sure the database has an entry for our new user.
			s.checkExists(strconv.Itoa(i), strconv.Itoa(i))

			// Check that the user was given an access_token and a refresh_token.
			s.verifyLoginCookies(rr.Result().Cookies())

			// Lastly, make sure that the mailer was called to send an email.
			s.Assert().True(m.sendEmailCalled, "code did not call SendEmail with mailer")
		}
	})

	s.Run("Test Duplicate Username", func() {
		s.SetupTest()
		// Make a fake request and response to probe the function with.
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Sign up for the first time.
		signup(m, s.db)(rr, r)

		// Make sure the database has an entry for our new user.
		s.checkExists(s.testCreds.Username, s.testCreds.Email)

		// Check that the user was given an access_token and a refresh_token.
		s.verifyLoginCookies(rr.Result().Cookies())

		// Make request with duplicate username.
		dupUserJSON := s.credsJSON(Credentials{
			Username: "GoldenBear321",
			Email:    "ast@gmail.com",
			Password: "123",
		})
		r = httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(dupUserJSON))
		rr = httptest.NewRecorder()

		//Signup with a duplicate username.
		signup(m, s.db)(rr, r)

		s.Assert().Equal(http.StatusConflict, rr.Code, "incorrect status code returned")
	})

	s.Run("Test Duplicate Email", func() {
		s.SetupTest()
		// Make a fake request and response to probe the function with.
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Sign up for the first time.
		signup(m, s.db)(rr, r)

		// Make sure the database has an entry for our new user.
		s.checkExists(s.testCreds.Username, s.testCreds.Email)

		// Check that the user was given an access_token and a refresh_token.
		s.verifyLoginCookies(rr.Result().Cookies())

		// Make request with duplicate username.
		dupEmailJSON := s.credsJSON(Credentials{
			Username: "JJ",
			Email:    "devops@berkeley.edu",
			Password: "123",
		})
		r = httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(dupEmailJSON))
		rr = httptest.NewRecorder()

		// Signup with a duplicate username.
		signup(m, s.db)(rr, r)

		s.Assert().Equal(http.StatusConflict, rr.Code, "incorrect status code returned")
	})
}

func (s *AuthTestSuite) TestSignin() {
	s.Run(("Test Basic Signin"), func() {
		s.SetupTest()
		//First create an user and have it sign up.
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Sign up for the first time.
		signup(m, s.db)(rr, r)

		// Make sure the database has an entry for our new user.
		s.checkExists(s.testCreds.Username, s.testCreds.Email)

		// Check that the user was given an access_token and a refresh_token.
		s.verifyLoginCookies(rr.Result().Cookies())

		//Let user sign in.
		r = httptest.NewRequest(http.MethodPost, "/api/auth/signin", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr = httptest.NewRecorder()
		signin(s.db)(rr, r)

		// Check that the user was given an access_token and a refresh_token.
		s.verifyLoginCookies(rr.Result().Cookies())
	})

	// Tests that the code will error when a user who hasn't tried to signup signs in
	s.Run(("Test Unassociated Email"), func() {
		s.SetupTest()
		//Let user sign in.
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signin", bytes.NewBuffer(s.credsJSON(Credentials{
			Username: "GoldenBear321",
			Email:    "cloud@berkeley.edu",
			Password: "DaddyDenero123",
		})))
		rr := httptest.NewRecorder()
		signin(s.db)(rr, r)

		//Check correct status returned.
		s.Assert().Equal(http.StatusBadRequest, rr.Result().StatusCode, "incorrect status code returned")
	})

	// Makes sure that a user cannot sign in with the wrong password
	s.Run(("Test Wrong Password"), func() {
		s.SetupTest()
		//First create an user and have it sign up.
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Sign up for the first time.
		signup(m, s.db)(rr, r)

		// Make sure the database has an entry for our new user.
		s.checkExists(s.testCreds.Username, s.testCreds.Email)

		// Check that the user was given an access_token and a refresh_token.
		s.verifyLoginCookies(rr.Result().Cookies())

		// Attempt to sign in with the same username and email, but a different password.
		r = httptest.NewRequest(http.MethodPost, "/api/auth/signin", bytes.NewBuffer(s.credsJSON(Credentials{
			Username: s.testCreds.Username,
			Email:    s.testCreds.Email,
			Password: "DaddyHilfinger123",
		})))
		rr = httptest.NewRecorder()
		signin(s.db)(rr, r)

		//Check correct status returned.
		s.Assert().Equal(http.StatusBadRequest, rr.Result().StatusCode, "incorrect status code returned")
	})
}

func (s *AuthTestSuite) TestLogout() {
	//First create an user and have it sign up.
	r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(s.credsJSON(s.testCreds)))
	rr := httptest.NewRecorder()
	m := newRecordMailer()

	// Sign up for the first time.
	signup(m, s.db)(rr, r)

	// Make sure the database has an entry for our new user.
	s.checkExists(s.testCreds.Username, s.testCreds.Email)

	// Check that the user was given an access_token and a refresh_token.
	cookies := rr.Result().Cookies()
	s.Require().Equal(2, len(cookies), "the incorrect amount of cookies were given back")
	s.verifyLoginCookies(cookies)

	// Let user log out of their account
	r = httptest.NewRequest(http.MethodPost, "/api/auth/logout", bytes.NewBuffer(s.credsJSON(s.testCreds)))
	// Add the cookies from before to this request.
	r.AddCookie(rr.Result().Cookies()[0])
	r.AddCookie(rr.Result().Cookies()[1])
	rr = httptest.NewRecorder()
	logout(rr, r)

	// Check that the user's access_token and refresh_token was set to expire.
	cookies = rr.Result().Cookies()
	if len(cookies) == 2 {
		s.Assert().True(cookies[0].Expires.Before(time.Now()), "%s cookie still exists and is not expired!", cookies[0].Name)
		s.Assert().True(cookies[1].Expires.Before(time.Now()), "%s cookie still exists and is not expired!", cookies[1].Name)
	}
}

func (s *AuthTestSuite) TestVerify() {
	s.Run("Test Valid Token", func() {
		s.SetupTest()
		// First create a user and have it sign up.
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Sign up
		signup(m, s.db)(rr, r)

		// Make sure user is not yet verified
		var verified bool
		err := s.db.QueryRow("SELECT verified FROM users WHERE email=?", s.testCreds.Email).Scan(&verified)
		if s.Assert().NoError(err) {
			s.Assert().False(verified, "user started out verified already")
		}

		// Get verification token from database
		var token string
		err = s.db.QueryRow("SELECT verifiedToken FROM users WHERE email=?", s.testCreds.Email).Scan(&token)
		s.Assert().NoError(err, "an error occurred while checking the database")

		// Create a fake request and response to probe the function with
		r = httptest.NewRequest(http.MethodPost, "/api/auth/verify", nil)
		rr = httptest.NewRecorder()
		q := url.Values{}
		q.Add("token", token)
		r.URL.RawQuery = q.Encode()

		// Call the function with our fake stuff
		verify(s.db)(rr, r)

		// Make sure user is now verified
		err = s.db.QueryRow("SELECT verified FROM users WHERE email=?", s.testCreds.Email).Scan(&verified)
		if s.Assert().NoError(err) {
			s.Assert().True(verified, "user was not verified")
		}
	})

	s.Run("Test Invalid Token", func() {
		s.SetupTest()
		// Create a fake request and response to probe the function with
		invalidToken := "bogusbogie123"
		r := httptest.NewRequest(http.MethodPost, "/api/auth/verify", nil)
		rr := httptest.NewRecorder()
		q := url.Values{}
		q.Add("token", invalidToken)
		r.URL.RawQuery = q.Encode()

		// Call the function with our fake stuff
		verify(s.db)(rr, r)

		// Make sure the correct status code is returned
		s.Assert().Equal(http.StatusBadRequest, rr.Result().StatusCode, "incorrect status code returned")

		// Make sure invalid token doesn't get stored in the database
		var exists bool
		err := s.db.QueryRow("SELECT EXISTS(SELECT * FROM users WHERE verifiedToken=?)", invalidToken).Scan(&exists)
		if s.Assert().NoError(err, "an error occurred while checking the database") {
			s.Assert().False(exists, "invalid token was saved in the database")
		}
	})
}

func (s *AuthTestSuite) TestReset() {
	newPassCreds := Credentials{
		Username: "GoldenBear321",
		Email:    "devops@berkeley.edu",
		Password: "Oski413",
	}

	s.Run("Test sendReset Valid Email", func() {
		s.SetupTest()
		// First create a user and have it sign up.
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Sign up
		signup(m, s.db)(rr, r)

		r = httptest.NewRequest(http.MethodPost, "/api/auth/sendreset", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr = httptest.NewRecorder()
		m = newRecordMailer()

		// Make request
		sendReset(m, s.db)(rr, r)

		// Make sure that the mailer was called to send an email.
		s.Assert().True(m.sendEmailCalled, "code did not call SendEmail with mailer")
	})

	s.Run("Test sendReset Invalid Email", func() {
		s.SetupTest()
		r := httptest.NewRequest(http.MethodPost, "/api/auth/sendreset", bytes.NewBuffer(s.credsJSON(Credentials{
			Username: "bears",
			Email:    "",
			Password: "asdf",
		})))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Make request
		sendReset(m, s.db)(rr, r)

		// Make sure the correct status code is returned
		s.Assert().Equal(http.StatusBadRequest, rr.Result().StatusCode, "incorrect status code returned")
	})

	s.Run("Test resetPassword Valid Token", func() {
		s.SetupTest()
		// First create a user and have it sign up.
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Sign up
		signup(m, s.db)(rr, r)

		// Now call sendReset
		r = httptest.NewRequest(http.MethodPost, "/api/auth/sendreset", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr = httptest.NewRecorder()
		m = newRecordMailer()

		sendReset(m, s.db)(rr, r)

		// Make sure that the mailer was called to send an email.
		s.Assert().True(m.sendEmailCalled, "code did not call SendEmail with mailer")

		// Get reset token from database
		var token string
		err := s.db.QueryRow("SELECT resetToken FROM users WHERE email=?", s.testCreds.Email).Scan(&token)
		s.Assert().NoError(err, "an error occurred while checking the database")

		// Now make the request
		r = httptest.NewRequest(http.MethodPost, "/api/auth/resetpw", bytes.NewBuffer(s.credsJSON(newPassCreds)))
		rr = httptest.NewRecorder()
		q := url.Values{}
		q.Add("token", token)
		r.URL.RawQuery = q.Encode()

		resetPassword(s.db)(rr, r)

		// Make sure password was changed
		var hashedPassword string
		err = s.db.QueryRow("SELECT hashedPassword FROM users WHERE email=?", s.testCreds.Email).Scan(&hashedPassword)
		s.Assert().NoError(err, "an error occurred while checking the database")

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(newPassCreds.Password))
		s.Assert().NoError(err, "password hash check failed")
	})

	s.Run("Test resetPassword Invalid Token", func() {
		s.SetupTest()
		// First create a user and have it sign up.
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Sign up
		signup(m, s.db)(rr, r)

		// Now call sendReset
		r = httptest.NewRequest(http.MethodPost, "/api/auth/sendreset", bytes.NewBuffer(s.credsJSON(s.testCreds)))
		rr = httptest.NewRecorder()
		m = newRecordMailer()

		sendReset(m, s.db)(rr, r)

		// Make sure that the mailer was called to send an email.
		s.Assert().True(m.sendEmailCalled, "code did not call SendEmail with mailer")

		// Now resetPassword
		invalidToken := "hehehe"
		r = httptest.NewRequest(http.MethodPost, "/api/auth/resetpw", bytes.NewBuffer(s.credsJSON(newPassCreds)))
		rr = httptest.NewRecorder()
		q := url.Values{}
		q.Add("token", invalidToken)
		r.URL.RawQuery = q.Encode()

		resetPassword(s.db)(rr, r)

		// Make sure status code is correct
		s.Assert().Equal(http.StatusBadRequest, rr.Result().StatusCode, "incorrect status code returned")

		// Make sure password was not changed
		var hashedPassword string
		err := s.db.QueryRow("SELECT hashedPassword FROM users WHERE email=?", newPassCreds.Email).Scan(&hashedPassword)
		s.Assert().NoError(err, "an error occurred while checking the database")

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(s.testCreds.Password))
		s.Assert().NoError(err)
	})
}

// HELPER METHODS AND DEFINITIONS

// Makes a Suite for all of the auth-service tests to live in
type AuthTestSuite struct {
	suite.Suite
	db        *sql.DB
	testCreds Credentials
}

// Clears the users database so the tests remain independent.
func (s *AuthTestSuite) clearDatabase() (err error) {
	_, err = s.db.Exec("TRUNCATE TABLE users")
	return err
}

// Returns true iff the cookie matches the expectations for signing up and signing in.
func (s *AuthTestSuite) verifyCookie(c *http.Cookie) bool {
	return (c.Name == "access_token" || c.Name == "refresh_token") &&
		c.Expires.After(time.Now()) &&
		c.Path == "/"
}

// Verify that the cookies array contains an access_token and a refresh_token
// with the correct attributes
func (s *AuthTestSuite) verifyLoginCookies(cookies []*http.Cookie) {
	if s.Assert().Equal(2, len(cookies), "the wrong amount of cookies were given back") {
		s.Assert().True(s.verifyCookie(cookies[0]), "first cookie does not have proper attributes")
		s.Assert().True(s.verifyCookie(cookies[1]), "second cookie does not have proper attributes")
		s.Assert().NotEqual(cookies[0].Name, cookies[1].Name, "two of the same cookie found")
	}
}

// Returns a byte array with a JSON containing the passed in Credentials. Useful for making basic requests.
func (s *AuthTestSuite) credsJSON(c Credentials) []byte {
	testCredsJSON, err := json.Marshal(c)

	// Makes sure the error returned here is nil.
	s.Require().NoErrorf(err, "failed to initialize test credentials %s", err)

	return testCredsJSON
}

// Verifies that a user with the passed in email and username is in the database.
func (s *AuthTestSuite) checkExists(username, email string) {
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT * FROM users WHERE email=? AND username=?)", email, username).Scan(&exists)
	if s.Assert().NoError(err, "an error occurred while checking the database") {
		s.Assert().True(exists, "could not find the user in the database after signing up")
	}
}

// Setup the db variable before any tests are run.
func (s *AuthTestSuite) SetupSuite() {
	// Connects to the MySQL Docker Container. Notice that we use localhost
	// instead of the container's IP address since it is assumed these
	// tests run outside of the container network.
	db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/auth")
	s.Require().NoError(err, "could not connect to the database!")
	s.db = db
	s.testCreds = Credentials{
		Username: "GoldenBear321",
		Email:    "devops@berkeley.edu",
		Password: "DaddyDenero123",
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
