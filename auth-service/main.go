package main

import (
	"log"
	"net/http"

	"github.com/BearCloud/sp21-bearchat/auth-service/api"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal(err.Error())
	}

	// Initialize the sendgrid client
	mailer := api.NewSendGridMailer()

	// Initialize our database connection
	db := api.InitDB()
	defer db.Close()

	// Ping the database to make sure it's up
	err = db.Ping()
	if err != nil {
		log.Println("Failed to ping database! Exiting with error...")
		panic(err.Error())
	}

	// Create a new mux for routing api calls
	router := mux.NewRouter()
	router.Use(CORS)
	router.Methods(http.MethodOptions)

	api.RegisterRoutes(router, mailer, db)

	log.Println("starting go server")
	http.ListenAndServe(":80", router)
}

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Set headers
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Origin", "<YOUR EC2 IP HERE>:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Next
		next.ServeHTTP(w, r)
	})
}
