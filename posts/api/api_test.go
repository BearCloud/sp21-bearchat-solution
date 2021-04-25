package api

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/dgrijalva/jwt-go"
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

// Runs all of the tests for the getPosts() function.
func TestGetPosts(t *testing.T) {
	suite.Run(t, new(GetPostsSuite))
}

// Tests that getPosts gives back the latest 25 posts in the database if there are
// more than 25 posts in it.
func (s *GetPostsSuite) TestBasicGetPosts() {
	// Insert 30 fake posts into the database.
	posts := s.insertFakePosts(30, "0", true)

	// Make a request to the posts endpoint for UUID 0 and get all posts starting from 0.
	rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/posts/0/0", nil)
	r.AddCookie(s.generateFakeAccessToken("0"))
	r = mux.SetURLVars(r, map[string]string{"uuid": "0", "startIndex": "0"})

	// Call the function.
	getPosts(s.db)(rr, r)

	// Check the status code.
	s.Require().Equal(http.StatusOK, rr.Result().StatusCode, "incorrect status code returned")

	// Make sure we got exactly 25 posts back.
	var returnedPosts []Post
	json.NewDecoder(rr.Result().Body).Decode(&returnedPosts)
	s.Require().Equal(25, len(returnedPosts), "incorrect number of posts returned")

	// Now check that the returned posts are in the correct order. Note because
	// of the issue with times mentioned below, we do the check manually.
	for i, post := range returnedPosts {
		// Normally you would use just time.Equal() here to compare them, but the way
		// we've set up our database makes it so it doesn't store times with
		// nanosecond precision (unlike Go's time.Time). Hence, the Equal checks will
		// fail. Rounding up to the nearest second solves the issue.
		s.Assert().True(posts[i].PostTime.Round(time.Second).Equal(post.PostTime.Round(time.Second)), "wrong time returned")

		// Check that the bodies are the same.
		s.Assert().Equal(posts[i].PostBody, post.PostBody, "wrong body returned")

		// Check that the authorID is correct.
		s.Assert().Equal(posts[i].AuthorID, post.AuthorID, "wrong author ID returned")

		// Check that the postID matches.
		s.Assert().Equal(posts[i].PostID, post.PostID, "wrong postID")
	}
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
	db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/postsDB?parseTime=true&loc=US%2FPacific")
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

// Inserts NUM number of fake posts into the database. Returns an array of them
// sorted by time in descending order (that is, the oldest posts are at the end
// of the returned array) if the last argument passed in is false.
// Also takes in an authorID for all of the posts.
func (s *PostsSuite) insertFakePosts(num int, authorID string, ascending bool) []Post {
	returnSlice := make([]Post, num)
	for i := 0; i < num; i += 1 {
		// Generate a random body for the post.
		returnSlice[i] = s.randomPost()

		// Sets the post time to be the current time minus i days.
		// This ensures that the posts are very spaced apart so there
		// is no room for small errors with the times being close. It also
		// ensures Posts created later on in the loop have an older/newer time
		// depending on the boolean so the array is always sorted.
		if ascending {
			returnSlice[i].PostTime = time.Now().AddDate(0, 0, i).Local()
		} else {
			returnSlice[i].PostTime = time.Now().AddDate(0, 0, -i).Local()
		}

		// Use the passed in ID for the authorID
		returnSlice[i].AuthorID = authorID

		// Also pick some non-conflicting IDs for the postIDs.
		returnSlice[i].PostID = strconv.Itoa(i)

		// Insert it into the database.
		p := returnSlice[i]
		_, err := s.db.Exec("INSERT INTO posts VALUES (?, ?, ?, ?)", p.PostBody, p.PostID, p.AuthorID, p.PostTime)
		s.Require().NoError(err, "there was an errror inserting a fake post")
	}
	return returnSlice
}

// Given a UUID, generates an access_token cookie that can be used to make requests
// for that UUID.
//
// NOTE: This is NOT a best practice (since the JWT key is hardcoded into the program).
// Make sure to keep your cryptographic keys private at all times!!! We do this since it
// is easy to test. We will likely not do it this way later on.
func (s *PostsSuite) generateFakeAccessToken(uuid string) *http.Cookie {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, AuthClaims{
		UserID: uuid,
		StandardClaims: jwt.StandardClaims{
			Subject:   "access",
			ExpiresAt: time.Now().AddDate(0, 0, 1).Unix(),
			Issuer:    "",
			IssuedAt:  time.Now().Unix(),
		},
	})
	tokenString, err := token.SignedString(jwtKey)
	s.Require().NoError(err, "could not make fake access token")
	return &http.Cookie{
		Name:    "access_token",
		Value:   tokenString,
		Expires: time.Now().AddDate(0, 0, 1),
	}
}
