package web

import (
	"encoding/json"
	"log"
	"net/http"
)

func Respond(w http.ResponseWriter, status int, errorType string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": errorType,
	})
}

func RespondContent(w http.ResponseWriter, status int, data any) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		log.Println("unable to encode response data with error: ", err)
	}
}
