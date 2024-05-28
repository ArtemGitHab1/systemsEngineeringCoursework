package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

// User структура представляющая пользователя
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Student структура представляющая студента
type Student struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Age  int    `json:"age"`
}

var users = []User{
	{ID: "1", Username: "user1", Password: "password1"},
	{ID: "2", Username: "user2", Password: "password2"},
}

var students = []Student{
	{ID: "1", Name: "John Doe", Age: 20},
	{ID: "2", Name: "Jane Smith", Age: 22},
}

var jwtKey = []byte("my_secret_key")

// Credentials структура представляющая данные для аутентификации
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims структура представляющая токен
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Проверка валидности токена
func validateToken(tokenString string) (bool, string) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return false, ""
	}
	if !token.Valid {
		return false, ""
	}
	return true, claims.Username
}

// Генерация токена
func generateToken(username string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// Обработчик для аутентификации и генерации токена
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusBadRequest)
		return
	}

	for _, user := range users {
		if user.Username == creds.Username && user.Password == creds.Password {
			token, err := generateToken(creds.Username)
			if err != nil {
				http.Error(w, "Failed to generate token", http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"token": token})
			return
		}
	}

	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

// Middleware для проверки токена
func tokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Token is missing", http.StatusUnauthorized)
			return
		}

		isValid, _ := validateToken(token)
		if !isValid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// Обработчик для получения списка студентов
func getStudentsHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(students)
}

// Обработчик для создания студента
func createStudentHandler(w http.ResponseWriter, r *http.Request) {
	var student Student
	err := json.NewDecoder(r.Body).Decode(&student)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	student.ID = fmt.Sprintf("%d", rand.Intn(100000))
	students = append(students, student)
	json.NewEncoder(w).Encode(student)
}

// Обработчик для обновления студента
func updateStudentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var updatedStudent Student
	err := json.NewDecoder(r.Body).Decode(&updatedStudent)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	for i, student := range students {
		if student.ID == id {
			students[i] = updatedStudent
			students[i].ID = id
			json.NewEncoder(w).Encode(students[i])
			return
		}
	}

	http.Error(w, "Student not found", http.StatusNotFound)
}

// Обработчик для удаления студента
func deleteStudentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	for i, student := range students {
		if student.ID == id {
			students = append(students[:i], students[i+1:]...)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	http.Error(w, "Student not found", http.StatusNotFound)
}

func main() {
	r := mux.NewRouter()

	// Маршрут для аутентификации и получения токена
	r.HandleFunc("/login", loginHandler).Methods("POST")

	// Маршрут для получения списка студентов (требует валидного токена)
	r.HandleFunc("/students", tokenMiddleware(getStudentsHandler)).Methods("GET")

	// Маршрут для создания студента (требует валидного токена)
	r.HandleFunc("/students", tokenMiddleware(createStudentHandler)).Methods("POST")

	// Маршрут для обновления студента (требует валидного токена)
	r.HandleFunc("/students/{id}", tokenMiddleware(updateStudentHandler)).Methods("PUT")

	// Маршрут для удаления студента (требует валидного токена)
	r.HandleFunc("/students/{id}", tokenMiddleware(deleteStudentHandler)).Methods("DELETE")

	http.ListenAndServe(":8000", r)
}
