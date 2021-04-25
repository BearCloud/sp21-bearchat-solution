package api

import (
	"database/sql"
	"log"
	"time"

	//MySQL driver
	_ "github.com/go-sql-driver/mysql"
)

func InitDB() *sql.DB {
	log.Println("attempting connections")
	var err error
	// We've decided to give the connection string for the rest of the microservices
	DB, err := sql.Open("mysql", "root:root@tcp(172.28.1.2:3306)/postsDB?parseTime=true&loc=US%2FPacific")

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
