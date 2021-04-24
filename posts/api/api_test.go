package api

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
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

// HELPER METHODS AND DEFINITIONS

// Defines the suite of tests for the entire Posts service.
type PostsSuite struct {
	suite.Suite
	db *sql.DB
}

// Defines a suite of tests for getPosts().
type GetPostsSuite struct {
	PostsSuite
}

// Defines a suite of tests for getFeed().
type GetFeedSuite struct {
	PostsSuite
}

// Defines a suite of tests for createPost().
type CreatePostSuite struct {
	PostsSuite
}

// Defines a suite of tests for deletePost().
type DeletePostSuite struct {
	PostsSuite
}

// Clears the posts database so the tests remain independent.
func (s *PostsSuite) clearDatabase() (err error) {
	_, err = s.db.Exec("TRUNCATE TABLE posts")
	return err
}

// Returns a byte array with a JSON containing the passed in Post. Useful for making basic requests.
func (s *PostsSuite) postJSON(p Post) []byte {
	JSON, err := json.Marshal(p)

	// Makes sure the error returned here is nil.
	s.Require().NoErrorf(err, "failed to initialize test post %s", err)

	return JSON
}

// Generates a post with random content. Note that this only fills the PostBody.
// All other fields will be empty.
func (s *PostsSuite) randomPost() Post {
	return Post{PostBody: gofakeit.Quote()}
}

// Verifies that a post with the same body as the one passed in exists in the
// database. If the test fails or the post couldn't be found, this returns false.
// Otherwise it returns true.
func (s *PostsSuite) verifyPostExists(p Post) bool {
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT * FROM posts WHERE content=?)", p.PostBody).Scan(&exists)
	if s.Assert().NoError(err, "error checking databse for the post") {
		return exists
	}
	return false
}

// Setup the db variable before any tests are run.
func (s *PostsSuite) SetupSuite() {
	// Connects to the MySQL Docker Container. Notice that we use localhost
	// instead of the container's IP address since it is assumed these
	// tests run outside of the container network.
	db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/postsDB?parseTime=true")
	s.Require().NoError(err, "could not connect to the database!")
	s.db = db
}

// Makes sure the database starts in a clean state before each test.
func (s *PostsSuite) SetupTest() {
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

	// Seeds the random post generator so we can get consistent tests.
	gofakeit.Seed(0)
}

// Given an HTTP method, API endpoint, and io.Reader, returns a ResponseRecorder and a fake Request
// that can be used for that endpoint. Makes the test fail with an error if any errors are
// encountered.
func (s *PostsSuite) generateRequestAndResponse(method, endpoint string, body io.Reader) (rr *httptest.ResponseRecorder, r *http.Request) {
	rr = httptest.NewRecorder()
	r, err := http.NewRequest(method, endpoint, body)
	s.Require().NoError(err, "could not initialize fake request and response")
	return rr, r
}
