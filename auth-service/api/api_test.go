package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// Returns true iff the cookie matches the expectations for signing up.
func verifyCookie(c *http.Cookie) bool {
	return (c.Name == "access_token" || c.Name == "refresh_token") &&
		c.Expires.After(time.Now()) &&
		c.Path == "/"
}

func clearDatabase(db *sql.DB) (err error) {
	_, err = db.Exec("TRUNCATE TABLE users")
	return err
}

// Contains the tests for signing up to Bearchat.
func TestSignup(t *testing.T) {
	testCreds := Credentials{
		Username: "GoldenBear321",
		Email:    "devops@berkeley.edu",
		Password: "DaddyDenero123",
	}
	testCredsJson, err := json.Marshal(testCreds)

	// Makes sure the error returned here is nil.
	require.Nil(t, err, "failed to initialize test credentials %s", err)

	// Connects to the MySQL Docker Container. Notice that we use localhost
	// instead of the container's IP address since it is assumed these
	// tests run outside of the container network.
	MySQLDB, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/auth")

	require.Nil(t, err, "failed to initialize database connection %s", err)

	// Runs a basic signup test using a mock database connection (meaning no database needs to be
	// started to run this test).
	t.Run("Test Basic Signup (No Database)", func(t *testing.T) {
		// Makes a new mock connection to the database. Now we don't have to start
		// an actual database server to test the code and we don't have to clean up!
		DB, mock, err := sqlmock.New()
		require.Nil(t, err, "an error '%s' was not expected when opening a stub database connection", err)
		defer DB.Close()

		// Makes a Mailer that will record whether or not SendEmail was called.
		m := newRecordMailer()

		// Makes a fake request to signup with basic credentials. Also makes a ResponseRecorder
		// to see what was written to the HTTP response.
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(testCredsJson))
		rr := httptest.NewRecorder()

		// Now we make our DB expectations.
		//
		// The code should check if the username already exists with SELECT EXISTS.
		mock.ExpectQuery("SELECT EXISTS").WithArgs(testCreds.Username).WillReturnRows(sqlmock.NewRows([]string{"col"}).AddRow(false))
		// The code should also check if someone with this email has already made an account.
		mock.ExpectQuery("SELECT EXISTS").WithArgs(testCreds.Email).WillReturnRows(sqlmock.NewRows([]string{"col"}).AddRow(false))
		// The code should try to insert a user into the database if all went well. They can do this with an INSERT INTO or REPLACE INTO
		mock.ExpectExec("(INSERT INTO|REPLACE INTO)").WithArgs(testCreds.Username, testCreds.Email, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

		// Invoke the route with everything we've setup.
		signup(m, DB)(rr, r)

		// First make sure that the request was given the proper status code.
		assert.Equal(t, http.StatusCreated, rr.Result().StatusCode, "expected status code %d but got %d", http.StatusCreated, rr.Result().StatusCode)

		// Make sure everything is good with regards to SQL queries.
		err = mock.ExpectationsWereMet()
		assert.Nil(t, err, err)

		// Check that the user was given an access_token and a refresh_token.
		cookies := rr.Result().Cookies()
		if assert.Equal(t, 2, len(cookies), "too many cookies returned") {
			assert.True(t, verifyCookie(cookies[0]), "first cookie does not have proper attributes")
			assert.True(t, verifyCookie(cookies[1]), "second cookie does not have proper attributes")
			assert.NotEqual(t, cookies[0].Name, cookies[1].Name, "two of the same cookie found")
		}

		// Lastly, make sure that the mailer was called to send an email.
		assert.True(t, m.sendEmailCalled, "code did not call SendEmail with mailer")
	})

	// This test actually makes use of the real MySQL database. This means you need to start it
	// for this test to work.
	t.Run("Test Basic Signup (Use Database)", func(t *testing.T) {
		// Make a fake request and response to probe the function with.
		r := httptest.NewRequest(http.MethodPost, "/api/auth/signup", bytes.NewBuffer(testCredsJson))
		rr := httptest.NewRecorder()
		m := newRecordMailer()

		// Make sure we're connected to the SQL database.
		err = MySQLDB.Ping()
		require.Nil(t, err, "could not connect to DB %s", err)

		// Make sure we're able to clear the database for this test.
		err = clearDatabase(MySQLDB)
		require.Nil(t, err, "could not clear database %s", err)

		// Call the function with our fake stuff.
		signup(m, MySQLDB)(rr, r)

		// Make sure the database has an entry for our new user.
		var exists bool
		err = MySQLDB.QueryRow("SELECT EXISTS(SELECT * FROM users WHERE email=? AND username=?)", testCreds.Email, testCreds.Username).Scan(&exists)
		assert.Nil(t, err, "an error occurred while checking the database %s", err)
		assert.True(t, exists, "could not find the user in the database after signing up")

		// Check that the user was given an access_token and a refresh_token.
		cookies := rr.Result().Cookies()
		if assert.Equal(t, 2, len(cookies), "too many cookies returned") {
			assert.True(t, verifyCookie(cookies[0]), "first cookie does not have proper attributes")
			assert.True(t, verifyCookie(cookies[1]), "second cookie does not have proper attributes")
			assert.NotEqual(t, cookies[0].Name, cookies[1].Name, "two of the same cookie found")
		}

		// Lastly, make sure that the mailer was called to send an email.
		assert.True(t, m.sendEmailCalled, "code did not call SendEmail with mailer")
	})
}
