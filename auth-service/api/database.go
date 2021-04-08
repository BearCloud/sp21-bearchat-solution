package api

import (
	"database/sql"
	"log"
	"time"

	// MySQL driver
	_ "github.com/go-sql-driver/mysql"
)

// DB represents the connection to the MySQL database
var (
	DB *sql.DB
)

// InitDB creates the MySQL database connection
func InitDB() *sql.DB {
	log.Println("attempting connections")
	// Open a SQL connection to the docker container hosting the database server
	// Assign the connection to the "DB" variable
	// Look at how it's done in the other microservices!
	DB, err := sql.Open("mysql", "root:root@tcp(172.28.1.2:3306)/auth")

	if err != nil {
		log.Print(err.Error())
		panic(err)
	}

	// Repeatedly Ping the database until no error to ensure it is up.
	for err = DB.Ping(); err != nil; err = DB.Ping() {
		log.Println("couldnt connect, waiting 10 seconds before retrying")
		time.Sleep(10 * time.Second)
	}

	return DB
}
