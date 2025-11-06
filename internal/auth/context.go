package auth

import "context"

type ctxKey string

var userIDKey ctxKey = "user_id"

func WithUserID(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

func UserIDFromContext(ctx context.Context) (int64, bool) {
	v := ctx.Value(userIDKey)
	if v == nil {
		return 0, false
	}
	if id, ok := v.(int64); ok {
		return id, true
	}
	return 0, false
}


