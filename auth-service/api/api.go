package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/sendgrid/sendgrid-go"
	"golang.org/x/crypto/bcrypt"
)

const (
	verifyTokenSize = 6
	resetTokenSize  = 6
)

// RegisterRoutes initializes the api endpoints and maps the requests to specific functions
func RegisterRoutes(router *mux.Router) error {
	router.HandleFunc("/api/auth/signup", signup).Methods(http.MethodPost)
	router.HandleFunc("/api/auth/signin", signin).Methods(http.MethodPost)
	router.HandleFunc("/api/auth/logout", logout).Methods(http.MethodPost)
	router.HandleFunc("/api/auth/verify", verify).Methods(http.MethodPost)
	router.HandleFunc("/api/auth/sendreset", sendReset).Methods(http.MethodPost)
	router.HandleFunc("/api/auth/resetpw", resetPassword).Methods(http.MethodPost)

	// Load sendgrid credentials
	err := godotenv.Load()
	if err != nil {
		return err
	}

	sendgridKey = os.Getenv("SENDGRID_KEY")
	sendgridClient = sendgrid.NewSendClient(sendgridKey)
	return nil
}

func signup(w http.ResponseWriter, r *http.Request) {
	// Obtain the credentials from the request body
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "error parsing credentials", http.StatusBadRequest)
		log.Print(err.Error())
		return
	}

	// Check if the username already exists
	var exists bool
	err = DB.QueryRow("SELECT EXISTS(SELECT * FROM users WHERE username=?)", creds.Username).Scan(&exists)

	// Check for error
	if err != nil {
		http.Error(w, "error checking if username exists", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Check boolean returned from query
	if exists {
		http.Error(w, "this username is taken", http.StatusConflict)
		return
	}

	// Check if the email already exists
	err = DB.QueryRow("SELECT EXISTS(SELECT * FROM users WHERE email=?)", creds.Email).Scan(&exists)

	// Check for error
	if err != nil {
		http.Error(w, "error checking if email exists", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Check boolean returned from query
	if exists {
		http.Error(w, "this email is taken", http.StatusConflict)
		return
	}

	// Hash the password using bcrypt and store the hashed password in a variable
	pass, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)

	// Check for errors during hashing process
	if err != nil {
		http.Error(w, "error preparing password for storage", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Create a new user UUID, convert it to string, and store it within a variable
	userID := uuid.New().String()

	// Create new verification token with the default token size (look at GetRandomBase62 and our constants)
	verifyToken := GetRandomBase62(verifyTokenSize)

	// Store credentials in database
	_, err = DB.Exec("INSERT INTO users VALUES (?, ?, ?, false, NULL, ?, ?)", creds.Username, creds.Email, pass, verifyToken, userID)

	// Check for errors in storing the credentials
	if err != nil {
		http.Error(w, "error storing credentials", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Generate an access token, expiry dates are in Unix time
	accessExpiresAt := time.Now().Add(DefaultAccessJWTExpiry)
	var accessToken string
	accessToken, err = setClaims(AuthClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			Subject:   "access",
			ExpiresAt: accessExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})

	// Check for error in generating an access token
	if err != nil {
		http.Error(w, "error generating access token", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Set the cookie, name it "access_token"
	http.SetCookie(w, &http.Cookie{
		Name:    "access_token",
		Value:   accessToken,
		Expires: accessExpiresAt,
		//Secure:   true,	// Since our website does not use HTTPS, this will make the cookie not send.
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
	})

	// Generate refresh token
	var refreshExpiresAt = time.Now().Add(DefaultRefreshJWTExpiry)
	var refreshToken string
	refreshToken, err = setClaims(AuthClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			Subject:   "refresh",
			ExpiresAt: refreshExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})

	if err != nil {
		http.Error(w, "error creating refreshToken", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Set the refresh token ("refresh_token") as a cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   refreshToken,
		Expires: refreshExpiresAt,
		Path:    "/",
	})

	// Send verification email
	err = SendEmail(creds.Email, "Email Verification", "user-signup.html", map[string]interface{}{"Token": verifyToken})
	if err != nil {
		http.Error(w, "error sending verification email", http.StatusInternalServerError)
		log.Print(err.Error())
	}

	w.WriteHeader(http.StatusCreated)
}

func signin(w http.ResponseWriter, r *http.Request) {
	// Store the credentials in a instance of Credentials
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)

	// Check for errors in storing credntials
	if err != nil {
		http.Error(w, "error parsing credentials", http.StatusBadRequest)
		return
	}

	// Get the hashedPassword and userId of the user
	var hashedPassword, userID string
	err = DB.QueryRow("SELECT hashedPassword, userID FROM users WHERE email=?", creds.Email).Scan(&hashedPassword, &userID)

	// Process errors associated with emails
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "this email is not associated with an account", http.StatusBadRequest)
		} else {
			http.Error(w, "error retrieving information with this email", http.StatusInternalServerError)
			log.Print(err.Error())
		}
		return
	}

	// Check if hashed password matches the one corresponding to the email
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(creds.Password))

	// Check error in comparing hashed passwords
	if err != nil {
		http.Error(w, "incorrect password", http.StatusBadRequest)
		return
	}

	// Generate an access token  and set it as a cookie (Look at signup and feel free to copy paste!)
	accessExpiresAt := time.Now().Add(DefaultAccessJWTExpiry)
	var accessToken string
	accessToken, err = setClaims(AuthClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			Subject:   "access",
			ExpiresAt: accessExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})

	if err != nil {
		http.Error(w, "error generating access token", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Expires:  accessExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
	})

	// Generate a refresh token and set it as a cookie (Look at signup and feel free to copy paste!)
	var refreshExpiresAt = time.Now().Add(DefaultRefreshJWTExpiry)
	var refreshToken string
	refreshToken, err = setClaims(AuthClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			Subject:   "refresh",
			ExpiresAt: refreshExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})

	if err != nil {
		http.Error(w, "error creating refreshToken", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   refreshToken,
		Expires: refreshExpiresAt,
		Path:    "/",
	})
}

func logout(w http.ResponseWriter, r *http.Request) {
	// Set the access_token and refresh_token to have an empty value and set their expiration date to anytime in the past
	var expiresAt = time.Now()
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "", Expires: expiresAt})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "", Expires: expiresAt})
}

func verify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	// Check that valid token exists
	if len(token) == 0 {
		http.Error(w, "url param 'token' is missing", http.StatusInternalServerError)
		log.Print("url param 'token' is missing")
		return
	}

	// Obtain the user with the verifiedToken from the query parameter and set their verification status to the integer "1"
	result, err := DB.Exec("UPDATE users SET verified=1 WHERE verifiedToken=?", token)

	// Check for errors in executing the previous query
	if err != nil {
		http.Error(w, "error setting the user to verified", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	if rows, err := result.RowsAffected(); rows != 1 || err != nil {
		http.Error(w, "invalid token", http.StatusBadRequest)
	}
}

func sendReset(w http.ResponseWriter, r *http.Request) {
	// Get the email from the body (decode into an instance of Credentials)
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)

	// Check for errors decoding the object
	if err != nil {
		http.Error(w, "could not parse request", http.StatusBadRequest)
		return
	}

	// Check for other miscallenous errors that may occur
	// What is considered an invalid input for an email?
	if creds.Email == "" {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}

	// Generate reset token
	token := GetRandomBase62(resetTokenSize)

	// Obtain the user with the specified email and set their resetToken to the token we generated
	_, err = DB.Query("UPDATE users SET resetToken=? WHERE email=?", token, creds.Email)

	// Check for errors executing the queries
	if err != nil {
		http.Error(w, "could not update reset token.", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Send verification email
	err = SendEmail(creds.Email, "BearChat Password Reset", "password-reset.html", map[string]interface{}{"Token": token})
	if err != nil {
		http.Error(w, "error sending verification email", http.StatusInternalServerError)
		log.Print(err.Error())
	}
}

func resetPassword(w http.ResponseWriter, r *http.Request) {
	// Get token from query params
	token := r.URL.Query().Get("token")

	// Get the username, email, and password from the body
	var credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)

	// Check for errors decoding the body
	if err != nil {
		http.Error(w, "could not parse request body", http.StatusBadRequest)
		return
	}

	// Check for invalid inputs, return an error if input is invalid
	if credentials.Email == "" || credentials.Username == "" || credentials.Password == "" {
		http.Error(w, "invalid body arguments", http.StatusBadRequest)
		return
	}

	// Check if the username and token pair exist
	username := credentials.Username
	password := credentials.Password
	var exists bool
	err = DB.QueryRow("SELECT * FROM users WHERE username=? AND resetToken=?", username, token).Scan(&exists)

	// Check for errors executing the query
	if err != nil {
		http.Error(w, "error executing token lookup", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Check exists boolean. Call an error if the username-token pair doesn't exist
	if !exists {
		http.Error(w, "invalid token for this user", http.StatusBadRequest)
		return
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Check for errors in hashing the new password
	if err != nil {
		http.Error(w, "password preparation failed", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Input new password and clear the reset token (set the token equal to empty string)
	_, err = DB.Exec("UPDATE users SET hashedPassword=?, resetToken=? WHERE username=?", hashedPassword, "", username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err.Error())
	}

	// Put the user in the redis cache to invalidate all current sessions (NOT IN SCOPE FOR PROJECT), leave this comment for future reference
}
