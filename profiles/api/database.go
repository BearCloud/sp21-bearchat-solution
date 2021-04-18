package api

import (
	"database/sql"
	"log"
	"time"

	// MySQL driver
	_ "github.com/go-sql-driver/mysql"
)

func InitDB() *sql.DB {
	log.Println("attempting connections")
	var err error
	db, err := sql.Open("mysql", "root:root@tcp(172.28.1.2:3306)/profiles")

	if err != nil {
		log.Print(err.Error())
		panic(err.Error())
	}

	for err = db.Ping(); err != nil; err = db.Ping() {
		log.Println("couldnt connect, waiting 10 seconds before retrying")
		time.Sleep(10 * time.Second)
	}

	return db
}
