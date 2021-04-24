package main

import (
	"log"
	"net/http"

	"github.com/BearCloud/sp21-bearchat/posts/api"
	"github.com/gorilla/mux"
)

func main() {
	DB := api.InitDB()
	defer DB.Close()

	// Ping the database to make sure it's up
	if err := DB.Ping(); err != nil {
		panic(err.Error())
	}
	// Create a new mux for routing api calls
	router := mux.NewRouter()
	router.Use(CORS)
	router.Methods(http.MethodOptions)

	api.RegisterRoutes(router, DB)

	log.Println("listening...")
	log.Fatal(http.ListenAndServe(":80", router))
}

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Set headers
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Origin", "<YOUR EC2 IP HERE>:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Next
		next.ServeHTTP(w, r)
	})
}
