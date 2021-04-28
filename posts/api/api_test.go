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
	"strings"
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

// Runs all of the tests for the createPost() function.
func TestCreatePost(t *testing.T) {
	suite.Run(t, new(CreatePostSuite))
}

// Runs all of the tests for the getFeed() function.
func TestGetFeed(t *testing.T) {
	suite.Run(t, new(GetFeedSuite))
}

// Runs all of the tests for the deletePost() function.
func TestDeletePost(t *testing.T) {
	suite.Run(t, new(DeletePostSuite))
}

// Tests that getPosts gives back the latest 25 posts in the database if there are
// more than 25 posts in it.
func (s *GetPostsSuite) TestBasic() {
	// Insert 30 fake posts into the database.
	expectedPosts := s.insertFakePosts(30, "0", true)

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
	s.Require().NoError(json.NewDecoder(rr.Result().Body).Decode(&returnedPosts), "could not decode response body")

	// Verify the posts we got back match expectations.
	s.verifyPosts(expectedPosts[:25], returnedPosts)
}

// Makes sure that the code gives valid error messages when a user
// is not authorized to see posts.
func (s *GetPostsSuite) TestUnauthorized() {
	s.Run("No Cookie", func() {
		// Generate a request without setting the cookie.
		rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/posts/0/0", nil)
		r = mux.SetURLVars(r, map[string]string{"uuid": "0", "startIndex": "0"})

		getPosts(s.db)(rr, r)

		// When the cookie is missing, the server should return a Status Bad Request.
		s.Assert().Equal(http.StatusBadRequest, rr.Result().StatusCode, "incorrect status code")
	})

	s.Run("Bad Cookie", func() {
		// Generate a request with an expired cookie.
		rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/posts/0/0", nil)
		r = mux.SetURLVars(r, map[string]string{"uuid": "0", "startIndex": "0"})
		cookie := s.generateFakeAccessToken("0")
		// The end of a JWT is the signature. This will almost certainly make the
		// signature invalid.
		cookie.Value = cookie.Value[:len(cookie.Value)-4] + "000"
		r.AddCookie(cookie)

		getPosts(s.db)(rr, r)

		// When the cookie is invalid, we should get a Status Unauthorized.
		s.Assert().Equal(http.StatusUnauthorized, rr.Result().StatusCode, "incorrect status code")
	})

	s.Run("Wrong Cookie", func() {
		// Generate a request with the cookie for another user.
		rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/posts/0/0", nil)
		r = mux.SetURLVars(r, map[string]string{"uuid": "0", "startIndex": "0"})
		r.AddCookie(s.generateFakeAccessToken("1"))

		getPosts(s.db)(rr, r)

		// When the cookie is for the wrong person, we should get a Status Unauthorized.
		s.Assert().Equal(http.StatusUnauthorized, rr.Result().StatusCode, "incorrect status code")
	})
}

// Makes sure that if the author has made less than 25 posts, getPosts()
// returns all of them.
func (s *GetPostsSuite) TestLessThan25Posts() {
	// Insert only 10 posts into the database.
	expectedPosts := s.insertFakePosts(10, "0", true)

	rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/posts/0/0", nil)
	r.AddCookie(s.generateFakeAccessToken("0"))
	r = mux.SetURLVars(r, map[string]string{"uuid": "0", "startIndex": "0"})

	getPosts(s.db)(rr, r)
	s.Require().Equal(http.StatusOK, rr.Result().StatusCode, "incorrect status code returned")

	// Make sure we got all 10 posts in the correct order.
	var returnedPosts []Post
	s.Require().NoError(json.NewDecoder(rr.Result().Body).Decode(&returnedPosts), "could not decode response body")
	s.verifyPosts(expectedPosts, returnedPosts)
}

// Tests that getPosts() only returns posts from the specified author
// and no one else.
func (s *GetPostsSuite) TestOnlyFromAuthor() {
	// Fill the database with some posts. After these calls, the database
	// will have 50 posts from AuthorIDs 0, 1, and 11. It will also have 1
	// post from AuthorID 10.
	s.insertFakePosts(50, "0", true)
	s.insertFakePosts(50, "1", true)
	s.insertFakePosts(50, "11", true)
	expectedPosts := s.insertFakePosts(1, "10", true)

	// Make a request to the posts endpoint for UUID 10 and get all posts starting from 0.
	rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/posts/10/0", nil)
	r.AddCookie(s.generateFakeAccessToken("10"))
	r = mux.SetURLVars(r, map[string]string{"uuid": "10", "startIndex": "0"})

	// Call the function.
	getPosts(s.db)(rr, r)

	// Check the status code.
	s.Require().Equal(http.StatusOK, rr.Result().StatusCode, "incorrect status code returned")

	// Make sure we got exactly 1 post back.
	var returnedPosts []Post
	s.Require().NoError(json.NewDecoder(rr.Result().Body).Decode(&returnedPosts), "could not decode response body")

	// Verify the posts we got back match expectations.
	s.verifyPosts(expectedPosts, returnedPosts)
}

// Makes sure that getPosts() can offset the posts by some amount.
func (s *GetPostsSuite) TestOffset() {
	// Insert 30 fake posts into the database.
	expectedPosts := s.insertFakePosts(30, "0", true)

	// Make a request to the posts endpoint for UUID 0 and get all posts starting from 10.
	rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/posts/0/10", nil)
	r.AddCookie(s.generateFakeAccessToken("0"))
	r = mux.SetURLVars(r, map[string]string{"uuid": "0", "startIndex": "10"})

	getPosts(s.db)(rr, r)

	// Make sure we got 20 of the posts back.
	s.Require().Equal(http.StatusOK, rr.Result().StatusCode, "incorrect status code returned")
	var returnedPosts []Post
	s.Require().NoError(json.NewDecoder(rr.Result().Body).Decode(&returnedPosts), "could not decode response body")
	s.verifyPosts(expectedPosts[10:30], returnedPosts)
}

// Makes sure that create post can simply insert a post into the database.
func (s *CreatePostSuite) TestBasic() {
	// Create a post that we will insert into the database.
	postToInsert := s.randomPost()

	// Generate a request that will hold our post and attach a cookie for userID 0.
	rr, r := s.generateRequestAndResponse(http.MethodPost, "/api/posts/create", bytes.NewBuffer(s.postJSON(postToInsert)))
	r.AddCookie(s.generateFakeAccessToken("0"))

	// Call the function to create the post in the database.
	createPost(s.db)(rr, r)

	s.Require().Equal(http.StatusCreated, rr.Result().StatusCode, "incorrect status code returned")

	// Make sure the post is in the database.
	postToInsert.AuthorID = "0"
	s.Require().True(s.verifyPostExists(postToInsert), "post was not inserted")
}

// Makes sure createPost() does not allow unauthorized post creation.
func (s *CreatePostSuite) TestUnauthorized() {
	// This is similar to TestBasic except we don't attach a cookie
	// to the request.
	s.Run("No Cookie", func() {
		postToInsert := s.randomPost()
		rr, r := s.generateRequestAndResponse(http.MethodPost, "/api/posts/create", bytes.NewBuffer(s.postJSON(postToInsert)))
		createPost(s.db)(rr, r)
		// No cookie should result in a StatusBadRequest.
		s.Require().Equal(http.StatusBadRequest, rr.Result().StatusCode, "incorrect status code returned")
		// Make sure the post is NOT in the database.
		postToInsert.AuthorID = "0"
		s.Require().False(s.verifyPostExists(postToInsert))
	})

	// This one just tests if the route returns an error if the JSON is bad.
	s.Run("Bad JSON", func() {
		rr, r := s.generateRequestAndResponse(http.MethodPost, "/api/posts/create", bytes.NewBuffer([]byte(`{oops:a bad json`)))
		r.AddCookie(s.generateFakeAccessToken("0"))
		createPost(s.db)(rr, r)
		s.Require().Equal(http.StatusBadRequest, rr.Result().StatusCode, "incorrect status code returned")
	})
}

// Makes sure that a basic SQL injection attack against createPost() fails.
// If you are failing this test make sure you are using ? in your SQL
// queries instead of directly inserting string values into queries!
func (s *CreatePostSuite) TestSQLInjection() {
	// Create a post that we will insert into the database. Notice
	// the body contains SQL commands :o. Don't execute the commands
	// in this post!!!
	postToInsert := Post{
		PostBody: `; INSERT INTO posts VALUES ("Evil Content", "100", "100", NULL); --`,
		AuthorID: `; INSERT INTO posts VALUES ("Evil Content", "101", "101", NULL); --`,
		PostID:   `; INSERT INTO posts VALUES ("Evil Content", "102", "102", NULL); --`,
	}

	// Generate a request that will hold our post and attach a cookie for userID 0.
	rr, r := s.generateRequestAndResponse(http.MethodPost, "/api/posts/create", bytes.NewBuffer(s.postJSON(postToInsert)))
	r.AddCookie(s.generateFakeAccessToken("0"))

	// Call the function to create the post in the database.
	createPost(s.db)(rr, r)

	// Notice that this should NOT error. The post should be put in like normal even with the SQL.
	s.Require().Equal(http.StatusCreated, rr.Result().StatusCode, "incorrect status code returned")

	// Make sure the post is in the database.
	postToInsert.AuthorID = "0"
	s.Require().True(s.verifyPostExists(postToInsert), "post was not inserted")
}

// Makes sure deletePost() can simply delete a post in the database.
func (s *DeletePostSuite) TestBasic() {
	// Adds a single post for us to delete.
	postToDelete := s.insertFakePosts(1, "0", true)[0]

	// Generate a request to delete the post.
	rr, r := s.generateRequestAndResponse(http.MethodDelete, "/api/posts/delete/"+postToDelete.PostID, nil)
	r = mux.SetURLVars(r, map[string]string{"postID": postToDelete.PostID})
	r.AddCookie(s.generateFakeAccessToken("0"))

	// Delete the post.
	deletePost(s.db)(rr, r)
	s.Require().Equal(http.StatusOK, rr.Result().StatusCode, "incorrect status code returned")

	// Make sure the post was indeed deleted.
	s.Require().False(s.verifyPostExists(postToDelete))
}

// Tests that deletePost() returns an error if there is no post with the given ID.
func (s *DeletePostSuite) TestNoPost() {
	// Generate a request to delete the post.
	rr, r := s.generateRequestAndResponse(http.MethodDelete, "/api/posts/delete/0", nil)
	r = mux.SetURLVars(r, map[string]string{"postID": "0"})
	r.AddCookie(s.generateFakeAccessToken("0"))

	// Delete the post.
	deletePost(s.db)(rr, r)
	s.Require().Equal(http.StatusNotFound, rr.Result().StatusCode, "incorrect status code returned")
}

// Tests that a user who is not authorized to delete posts is not allowed to.
func (s *DeletePostSuite) TestUnauthorized() {
	postToDelete := s.insertFakePosts(1, "0", true)[0]
	s.Run("No Cookie", func() {
		// Generate the request without putting a cookie in it.
		rr, r := s.generateRequestAndResponse(http.MethodDelete, "/api/posts/delete/"+postToDelete.PostID, nil)
		r = mux.SetURLVars(r, map[string]string{"postID": postToDelete.PostID})
		deletePost(s.db)(rr, r)

		// No cookie means BadRequest.
		s.Require().Equal(http.StatusBadRequest, rr.Result().StatusCode, "incorrect status code")

		// Make sure the post still exists.
		s.Require().True(s.verifyPostExists(postToDelete), "post was deleted")
	})

	// Makes sure the person trying to delete the post is the one who made it.
	s.Run("Author Mistmatch", func() {
		// Generate the request with a cookie for a different user than the one
		// who created the Post.
		rr, r := s.generateRequestAndResponse(http.MethodDelete, "/api/posts/delete/"+postToDelete.PostID, nil)
		r = mux.SetURLVars(r, map[string]string{"postID": postToDelete.PostID})
		r.AddCookie(s.generateFakeAccessToken("1"))
		deletePost(s.db)(rr, r)

		// Wrong author means they are Unauthorized
		s.Require().Equal(http.StatusUnauthorized, rr.Result().StatusCode, "incorrect status code")

		// Make sure the post still exists.
		s.Require().True(s.verifyPostExists(postToDelete), "post was deleted")
	})
}

// Makes sure that getFeed() works when there are 25 posts from other users.
func (s *GetFeedSuite) TestBasic() {
	// Insert 25 posts from user 1 into the database.
	expectedPosts := s.insertFakePosts(25, "1", true)

	// Make a request to the posts endpoint to get all posts starting from 0.
	rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/posts/0", nil)
	r.AddCookie(s.generateFakeAccessToken("0"))
	r = mux.SetURLVars(r, map[string]string{"startIndex": "0"})

	// Call the function.
	getFeed(s.db)(rr, r)

	// Check the status code.
	s.Require().Equal(http.StatusOK, rr.Result().StatusCode, "incorrect status code returned")

	// Make sure we got exactly 25 posts back.
	var returnedPosts []Post
	s.Require().NoError(json.NewDecoder(rr.Result().Body).Decode(&returnedPosts), "could not decode response body")

	// Verify the posts we got back match expectations.
	s.verifyPosts(expectedPosts, returnedPosts)
}

// Makes sure that getFeed() works when there are less than 25 posts from other users.
func (s *GetFeedSuite) TestLessThan25Posts() {
	// Insert 10 posts from user 1 into the database.
	expectedPosts := s.insertFakePosts(10, "1", true)

	// Make a request to the posts endpoint to get all posts starting from 0.
	rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/posts/0", nil)
	r.AddCookie(s.generateFakeAccessToken("0"))
	r = mux.SetURLVars(r, map[string]string{"startIndex": "0"})

	getFeed(s.db)(rr, r)
	s.Require().Equal(http.StatusOK, rr.Result().StatusCode, "incorrect status code returned")

	// Make sure we got exactly 10 posts back.
	var returnedPosts []Post
	s.Require().NoError(json.NewDecoder(rr.Result().Body).Decode(&returnedPosts), "could not decode response body")
	s.verifyPosts(expectedPosts, returnedPosts)
}

// Tests that getFeed() returns posts only from other users
// and not the author.
func (s *GetFeedSuite) TestMixed() {
	// Insert 100 posts from AuthorID 0 and 1 from AuthorID 1.
	s.insertFakePosts(100, "0", true)
	expectedPosts := s.insertFakePosts(1, "1", true)

	// Make a request with id 0.
	rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/posts/0", nil)
	r.AddCookie(s.generateFakeAccessToken("0"))
	r = mux.SetURLVars(r, map[string]string{"startIndex": "0"})

	getFeed(s.db)(rr, r)
	s.Require().Equal(http.StatusOK, rr.Result().StatusCode, "incorrect status code returned")

	// Make sure we only got the post from user id 1 back.
	var returnedPosts []Post
	s.Require().NoError(json.NewDecoder(rr.Result().Body).Decode(&returnedPosts), "could not decode response body")
	s.verifyPosts(expectedPosts, returnedPosts)
}

// Tests that only authorized people can access the feed.
func (s *GetFeedSuite) TestUnauthorized() {
	// Generate a request without setting the cookie.
	rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/posts/0", nil)
	r = mux.SetURLVars(r, map[string]string{"startIndex": "0"})

	getFeed(s.db)(rr, r)

	// When the cookie is missing, the server should return a Status Bad Request.
	s.Assert().Equal(http.StatusBadRequest, rr.Result().StatusCode, "incorrect status code")
}

// Test that getFeed() works with an offset.
func (s *GetFeedSuite) TestOffset() {
	// Insert 100 posts from user 1 into the database.
	expectedPosts := s.insertFakePosts(100, "1", true)

	// Make a request to the posts endpoint to get all posts starting from 50.
	rr, r := s.generateRequestAndResponse(http.MethodGet, "/api/posts/50", nil)
	r.AddCookie(s.generateFakeAccessToken("0"))
	r = mux.SetURLVars(r, map[string]string{"startIndex": "50"})

	getFeed(s.db)(rr, r)
	s.Require().Equal(http.StatusOK, rr.Result().StatusCode, "incorrect status code returned")

	// Make sure we got exactly 25 posts back.
	var returnedPosts []Post
	s.Require().NoError(json.NewDecoder(rr.Result().Body).Decode(&returnedPosts), "could not decode response body")
	s.verifyPosts(expectedPosts[50:75], returnedPosts)
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
	s.Require().NoErrorf(err, "failed to initialize test post %s", err)
	return JSON
}

// Generates a post with random content. Note that this only fills the PostBody.
// All other fields will be empty.
func (s *PostsSuite) randomPost() Post {
	return Post{PostBody: gofakeit.Quote()}
}

// Verifies that a post with the same body and AuthorID as the one passed in exists in the
// database. It also makes sure the post doesn't have a NULL postID and time.
// If the test fails or the post couldn't be found, this returns false.
// Otherwise it returns true.
func (s *PostsSuite) verifyPostExists(p Post) bool {
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT * FROM posts WHERE content=? AND authorID=? AND postID IS NOT NULL AND postTime IS NOT NULL)", p.PostBody, p.AuthorID).Scan(&exists)
	if s.Assert().NoError(err, "error checking database for the post") {
		return exists
	}
	return false
}

// Setup the db variable before any tests are run.
func (s *PostsSuite) SetupSuite() {
	// Connects to the MySQL Docker Container. Notice that we use localhost
	// instead of the container's IP address since it is assumed these
	// tests run outside of the container network. If you weren't being lazy
	// like us, you'd probably put this string into a .env file so it's secret
	// and it's easy to change out if you change the database.
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
	gofakeit.Seed(1)
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
	if num <= 0 {
		return returnSlice
	}
	// Spicy query line. Just duplicates (?, ?, ?, ?) a bunch of times after the
	// word VALUES so we can insert everything at once. See below why we do this.
	query := "INSERT INTO posts VALUES " + strings.Repeat("(?, ?, ?, ?), ", num)
	// Trims the last comma and space off the end.
	query = query[:len(query)-2]
	var queryParams []interface{}
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
		returnSlice[i].PostID = gofakeit.UUID()

		// Now save the values from this Post so we can put them into a query.
		queryParams = append(queryParams, returnSlice[i].PostBody, returnSlice[i].PostID, returnSlice[i].AuthorID, returnSlice[i].PostTime)
	}

	// Now insert into the database. Notice that we do this after creating all the
	// Posts instead of during the loop. This is an optimization since, if we did
	// it during the loop, we would make NUM queries to the database and that takes longer
	// than making one single query. This is often called an n+1 queries problem.
	_, err := s.db.Exec(query, queryParams...)
	s.Require().NoError(err, "failed to insert into the database")

	// Return the posts.
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

// Verifies that the expected and actual slices of posts meet expectations. Fails
// the current test if not.
func (s *PostsSuite) verifyPosts(expected, actual []Post) {
	// Make sure we got the right postst back
	s.Require().Equal(len(expected), len(actual), "incorrect number of posts returned")

	// Now check that the returned posts are in the correct order. Note because
	// of the issue with times mentioned below, we do the check manually.
	for i, returnedPost := range actual {
		// Normally you would use just time.Equal() here to compare them, but the way
		// we've set up our database makes it so it doesn't store times with
		// nanosecond precision (unlike Go's time.Time). Hence, the Equal checks will
		// fail. Rounding up to the nearest second solves the issue.
		s.Assert().True(expected[i].PostTime.Round(time.Second).Equal(returnedPost.PostTime.Round(time.Second)), "wrong time returned")

		// Check that the bodies are the same.
		s.Assert().Equal(expected[i].PostBody, returnedPost.PostBody, "wrong body returned")

		// Check that the authorID is correct.
		s.Assert().Equal(expected[i].AuthorID, returnedPost.AuthorID, "wrong author ID returned")

		// Check that the postID matches.
		s.Assert().Equal(expected[i].PostID, returnedPost.PostID, "wrong postID")
	}
}
