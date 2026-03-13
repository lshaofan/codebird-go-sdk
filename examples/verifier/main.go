package main

import (
	"encoding/json"
	"log"
	"net/http"

	codebird "github.com/lshaofan/codebird-go-sdk"
)

func main() {
	verifier, err := codebird.NewVerifier(codebird.Config{
		Issuer:   "https://auth.codebird.cloud",
		Audience: "https://api.example.com",
	})
	if err != nil {
		log.Fatalf("failed to create verifier: %v", err)
	}

	http.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		token, err := codebird.ParseBearerToken(r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		authContext, err := verifier.VerifyAccessToken(r.Context(), token)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":         authContext.Subject,
			"email":           authContext.Email,
			"organization_id": authContext.OrganizationID,
			"roles":           authContext.OrganizationRoles,
		})
	})

	log.Println("go verifier example listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
