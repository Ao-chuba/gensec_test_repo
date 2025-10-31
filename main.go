package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os/exec"

	_ "github.com/go-sql-driver/mysql" // We import the driver for sql.Open
)

// Vulnerability 1: Hardcoded sensitive data
var adminAPIKey = "super-secret-key-12345-do-not-steal"

// Vulnerability 2: Command Injection
// This handler is supposed to check if a host is online.
func handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	// Get 'host' parameter from the URL, e.g., /status?host=8.8.8.8
	host := r.URL.Query().Get("host")

	// DANGEROUS: The 'host' variable is directly concatenated into a shell command.
	// An attacker can pass '8.8.8.8; ls' to run the 'ls' command.
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error: %s\n", err)
		return
	}

	fmt.Fprintf(w, "Output: %s\n", out)
}

// Vulnerability 3: SQL Injection
// This handler is supposed to fetch user details.
func handleGetUser(w http.ResponseWriter, r *http.Request) {
	// Get 'id' parameter from the URL, e.g., /user?id=123
	userID := r.URL.Query().Get("id")

	// This connection string is just for the example to compile.
	// The vulnerability is in the query building, not the connection itself.
	db, err := sql.Open("mysql", "user:password@/dbname")
	if err != nil {
		http.Error(w, "DB connection error (dummy)", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// DANGEROUS: The 'userID' variable is concatenated directly into the SQL query string.
	// An attacker can pass '123 OR 1=1' to bypass authentication or dump data.
	query := "SELECT name, email FROM users WHERE id = " + userID

	log.Printf("Executing query: %s", query)
	
	// The vulnerable query would be executed here.
	// We'll just print a success message for this example.
	// In a real app, db.Query(query) would be called.
	fmt.Fprintf(w, "Successfully queried for user (simulation): %s", userID)
}

func main() {
	fmt.Println("Vulnerable server starting on :8080...")
	fmt.Printf("WARNING: The admin API key is: %s\n", adminAPIKey)
	fmt.Println("This application contains deliberate vulnerabilities for testing.")

	http.HandleFunc("/status", handleSystemStatus)
	http.HandleFunc("/user", handleGetUser)

	log.Fatal(http.ListenAndServe(":8080", nil))
}