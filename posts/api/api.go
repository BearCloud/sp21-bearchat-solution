package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func RegisterRoutes(router *mux.Router, db *sql.DB) {
	// Spicy regex on the path names to help with integers :^).
	router.HandleFunc("/api/posts/{startIndex:[0-9]+}", getFeed(db)).Methods(http.MethodGet)
	router.HandleFunc("/api/posts/{uuid}/{startIndex:[0-9]+}", getPosts(db)).Methods(http.MethodGet)
	router.HandleFunc("/api/posts/create", createPost(db)).Methods(http.MethodPost)
	router.HandleFunc("/api/posts/delete/{postID}", deletePost(db)).Methods(http.MethodDelete)
}

func getPosts(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Load the uuid and startIndex from the url paramater into their own variables
		// Look at mux.Vars() ... -> https://godoc.org/github.com/gorilla/mux#Vars
		// Make sure to use "strconv" to convert the startIndex to an integer!
		uuid := mux.Vars(r)["uuid"]
		start := mux.Vars(r)["startIndex"]
		startIndex, err := strconv.Atoi(start)

		if err != nil {
			http.Error(w, "could not parse startIndex from request", http.StatusBadRequest)
			return
		}

		// Check if the user is authorized
		// First get the uuid from the access_token (see getUUID())
		// Compare that to the uuid we got from the url parameters, if they're not the same, return an error http.StatusUnauthorized
		userID, err := getUUID(w, r)

		if err != nil {
			return
		}

		if userID != uuid {
			http.Error(w, "you are not authorized to access these posts", http.StatusUnauthorized)
			return
		}

		// -Get all that posts that matches our userID (or uuid)
		// -Sort them chronologically (the database has a "postTime" field), hint: ORDER BY
		// -Make sure to always get up to 25, and start with an offset of {startIndex} (look at the previous SQL homework for hints)
		// -As indicated by the "posts" variable, this query returns multiple rows
		posts, err := db.Query("SELECT * FROM posts WHERE authorID=? ORDER BY postTime ASC LIMIT 25 OFFSET ?", userID, startIndex)

		// Check for errors from the query
		if err != nil {
			http.Error(w, "could not get posts", http.StatusInternalServerError)
			log.Println(err.Error())
			return
		}

		var (
			content  string
			postID   string
			userid   string
			postTime time.Time
		)
		numPosts := 0
		// Create "postsArray", which is a slice (array) of Posts. Make sure it has size 25
		// Hint: https://tour.golang.org/moretypes/13
		postsArray := make([]Post, 25)

		for i := 0; i < 25 && posts.Next(); i++ {
			// Every time we call posts.Next() we get access to the next row returned from our query
			// Question: How many columns did we return
			// Reminder: Scan() scans the rows in order of their columns. See the variables defined up above for your convenience
			err = posts.Scan(&content, &postID, &userid, &postTime)

			// Check for errors in scanning
			if err != nil {
				http.Error(w, "there was an error retreiving your posts", http.StatusInternalServerError)
				log.Print(err.Error())
				return
			}

			// Set the i-th index of postsArray to a new Post with values directly from the variables you just scanned into
			// Check post.go for the structure of a Post
			// Hint: https://gobyexample.com/structs
			postsArray[i] = Post{content, postID, userid, postTime}
			numPosts++
		}

		err = posts.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		err = posts.Err()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}
		// Encode fetched data as json and serve to client
		// Up until now, we've actually been counting the number of posts (numPosts)
		// We will always have *up to* 25 posts, but we can have less
		// However, we already allocated 25 spots in our postsArray
		// Return the subarray that contains all of our values (which may be a subsection of our array or the entire array)
		json.NewEncoder(w).Encode(postsArray[0:numPosts])
	}
}

func createPost(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Obtain the userID from the JSON Web Token
		// See getUUID(...)
		userID, err := getUUID(w, r)
		if err != nil {
			return
		}

		// Create a Post object and then Decode the JSON Body (which has the structure of a Post) into that object
		var post Post
		err = json.NewDecoder(r.Body).Decode(&post)
		if err != nil {
			http.Error(w, "could not decode post information from body", http.StatusBadRequest)
			return
		}

		// Use the uuid library to generate a post ID
		// Hint: https://godoc.org/github.com/google/uuid#New
		postID := uuid.New()

		// Insert the post into the database
		// Look at /db-server/initdb.sql for a better understanding of what you need to insert
		result, err := db.Exec("INSERT INTO posts VALUES (?, ?, ?, ?)", post.PostBody, postID, userID, time.Now())

		// Check errors with executing the query
		if err != nil {
			http.Error(w, "error storing post into the database", http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		// Make sure at least one row was affected, otherwise return an InternalServerError
		// You did something very similar in Checkpoint 2
		if rows, err := result.RowsAffected(); rows < 1 || err != nil {
			http.Error(w, "database unaffected by post creation", http.StatusInternalServerError)
			return
		}

		// What kind of HTTP header should we return since we created something?
		// Check your signup from Checkpoint 2!
		w.WriteHeader(http.StatusCreated)
	}
}

func deletePost(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the postID to delete
		// Look at mux.Vars() ... -> https://godoc.org/github.com/gorilla/mux#Vars
		postID := mux.Vars(r)["postID"]
		// Get the uuid from the access token, see getUUID(...)
		userID, err := getUUID(w, r)
		if err != nil {
			return
		}

		var exists bool
		// Check if post exists
		err = db.QueryRow("SELECT EXISTS (SELECT * FROM posts WHERE postID=?)", postID).Scan(&exists)

		// Check for errors in executing the query
		if err != nil {
			http.Error(w, "error finding post", http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		// Check if the post actually exists, otherwise return an http.StatusNotFound
		if !exists {
			http.Error(w, "post does not exist", http.StatusNotFound)
			return
		}

		// Get the authorID of the post with the specified postID
		var authorID string
		err = db.QueryRow("SELECT authorID FROM posts WHERE postID=?", postID).Scan(&authorID)

		// Check for errors in executing the query
		if err != nil {
			http.Error(w, "error finding authorID of post", http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		// Check if the uuid from the access token is the same as the authorID from the query
		// If not, return http.StatusUnauthorized
		if userID != authorID {
			http.Error(w, "you are not the author of this post", http.StatusUnauthorized)
			return
		}

		// Delete the post since by now we're authorized to do so
		_, err = db.Exec("DELETE FROM posts WHERE postID=?", postID)

		// Check for errors in executing the query
		if err != nil {
			http.Error(w, "could not delete post", http.StatusInternalServerError)
			log.Print(err.Error())
		}
	}
}

func getFeed(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get the start index from the url paramaters
		// based on the previous functions, you should be familiar with how to do so
		start, ok := mux.Vars(r)["startIndex"]
		if !ok {
			http.Error(w, "start index not detected in URL", http.StatusBadRequest)
			return
		}

		// Convert startIndex to int
		startIndex, err := strconv.Atoi(start)

		// Check for errors in converting
		// If error, return http.StatusBadRequest
		if err != nil {
			http.Error(w, "could not parse startIndex from URL", http.StatusBadRequest)
			return
		}

		// Get the userID from the access_token
		// You should now be familiar with how to do so
		userID, err := getUUID(w, r)
		if err != nil {
			return
		}

		// Obtain all of the posts where the authorID is *NOT* the current authorID
		// Sort chronologically
		// Always limit to 25 queries
		// Always start at an offset of startIndex
		posts, err := db.Query("SELECT * FROM posts WHERE authorID<>? ORDER BY postTime LIMIT 25", userID, startIndex)

		// Check for errors in executing the query
		if err != nil {
			http.Error(w, "there was an error retreiving your feed", http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		var (
			content  string
			postID   string
			userid   string
			postTime time.Time
		)

		// Put all the posts into an array of Max Size 25 and return all the filled spots
		// Almost exactly like getPosts()
		postsArray, numPosts := make([]Post, 25), 0
		for i := 0; i < 25 && posts.Next(); i++ {
			err = posts.Scan(&content, &postID, &userid, &postTime)

			// Check for errors in scanning
			if err != nil {
				http.Error(w, "there was an error retreiving your posts", http.StatusInternalServerError)
				log.Print(err.Error())
				return
			}

			// Set the i-th index of postsArray to a new Post with values directly from the variables you just scanned into
			// Check post.go for the structure of a Post
			// Hint: https://gobyexample.com/structs
			postsArray[i] = Post{content, postID, userid, postTime}
			numPosts++
		}

		posts.Close()
		err = posts.Err()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}
		json.NewEncoder(w).Encode(postsArray[0:numPosts])
	}
}
