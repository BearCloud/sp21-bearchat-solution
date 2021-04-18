package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func RegisterRoutes(router *mux.Router, db *sql.DB) {
	router.HandleFunc("/api/profile/{uuid}", getProfile(db)).Methods(http.MethodGet)
	router.HandleFunc("/api/profile/{uuid}", updateProfile(db)).Methods(http.MethodPut)
}

func getProfile(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Obtain the uuid from the url path and store it in a `uuid` variable
		// Hint: mux.Vars()
		uuid := mux.Vars(r)["uuid"]

		// Initialize a new Profile variable
		p := Profile{}

		// Obtain all the information associated with the requested uuid
		// Scan the information into the profile struct's variables
		// Remember to pass in the address!
		err := db.QueryRow("SELECT * FROM users WHERE uuid=?", uuid).Scan(&p.Firstname, &p.Lastname, &p.Email, &p.UUID)

		// If we could not find any users in the database with this UUID,
		// return a BadRequest.
		if err == sql.ErrNoRows {
			http.Error(w, "could not find a user with that UUID", http.StatusBadRequest)
			return
		}

		// Check for errors with querying the database
		// Return an Internal Server Error if such an error occurs
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Println(err.Error())
			return
		}

		// Encode fetched data as json and serve to client
		err = json.NewEncoder(w).Encode(p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Println(err.Error())
		}
	}
}

func updateProfile(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Obtain the requested uuid from the url path and store it in a `uuid` variable
		uuid := mux.Vars(r)["uuid"]

		// Obtain the userID from the cookie. See jwt.go.
		cookieUUID, err := getUUID(w, r)
		if err != nil {
			return
		}

		// If the two ID's don't match, return a StatusUnauthorized
		if cookieUUID != uuid {
			http.Error(w, "you cannot update this profile", http.StatusUnauthorized)
			return
		}

		// Decode the Request Body's JSON data into a profile variable
		var p Profile
		err = json.NewDecoder(r.Body).Decode(&p)

		// Return an InternalServerError if there is an error decoding the request body
		if err != nil {
			// May need to change this to StatusBadRequest
			http.Error(w, "could not parse request", http.StatusInternalServerError)
			return
		}

		// Insert the profile data into the users table
		// Check db-server/initdb.sql for the scheme
		// Make sure to use REPLACE INTO
		_, err = db.Exec("REPLACE INTO users VALUES (?, ?, ?, ?)", p.Firstname, p.Lastname, p.Email, p.UUID)

		// Return an internal server error if any errors occur when querying the database.
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Println(err.Error())
			return
		}
	}
}
