package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/api/profile/{uuid}", getProfile).Methods(http.MethodGet)
	router.HandleFunc("/api/profile/{uuid}", updateProfile).Methods(http.MethodPut)
}

func getUUID(w http.ResponseWriter, r *http.Request) (uuid string, err error) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		http.Error(w, "error obtaining cookie: "+err.Error(), http.StatusBadRequest)
		return "", err
	}
	// Validate the cookie
	claims, err := ValidateToken(cookie.Value)
	if err != nil {
		http.Error(w, "error validating token: "+err.Error(), http.StatusUnauthorized)
		return "", err
	}

	return claims["UserID"].(string), nil
}

func getProfile(w http.ResponseWriter, r *http.Request) {

	// Obtain the uuid from the url path and store it in a `uuid` variable
	// Hint: mux.Vars()
	uuid := mux.Vars(r)["uuid"]

	// Initialize a new Profile variable
	p := Profile{}

	// Obtain all the information associated with the requested uuid
	// Scan the information into the profile struct's variables
	// Remember to pass in the address!
	err := DB.QueryRow("SELECT * FROM users WHERE uuid=?", uuid).Scan(&p.Firstname, &p.Lastname, &p.Email, &p.UUID)

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

func updateProfile(w http.ResponseWriter, r *http.Request) {
	// Obtain the requested uuid from the url path and store it in a `uuid` variable
	uuid := mux.Vars(r)["uuid"]

	// Obtain the userID from the cookie
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
	// Make sure to use REPLACE INTO (as covered in the SQL homework)
	result, err := DB.Exec("REPLACE INTO users VALUES (?, ?, ?, ?)", p.Firstname, p.Lastname, p.Email, p.UUID)

	// Return an internal server error if any errors occur when querying the database.
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err.Error())
		return
	}

	if r, err := result.RowsAffected(); r < 1 || err != nil {
		http.Error(w, "there was an error updating your profile", http.StatusBadRequest)
	}
}
