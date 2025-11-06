package middleware

import (
	"net/http"
	"strings"

	"whisperwire/internal/auth"
	"whisperwire/internal/resp"
)

func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if authz == "" || !strings.HasPrefix(authz, "Bearer ") {
			resp.WriteError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid Authorization header")
			return
		}
		token := strings.TrimPrefix(authz, "Bearer ")
		_, userID, err := auth.ParseToken(token)
		if err != nil {
			resp.WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid token")
			return
		}
		ctx := auth.WithUserID(r.Context(), userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}


