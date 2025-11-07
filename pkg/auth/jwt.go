package auth

import (
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID int64 `json:"uid"`
	jwt.RegisteredClaims
}

func getSecret() ([]byte, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, errors.New("JWT_SECRET is not set")
	}
	return []byte(secret), nil
}

func getAccessMinutes() int {
	if v := os.Getenv("ACCESS_TOKEN_MIN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 15
}

func getRefreshDays() int {
	if v := os.Getenv("REFRESH_TOKEN_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 7
}

func GenerateAccessToken(userID int64) (string, error) {
	secret, err := getSecret()
	if err != nil {
		return "", err
	}
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(getAccessMinutes()) * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func GenerateRefreshToken(userID int64) (string, error) {
	secret, err := getSecret()
	if err != nil {
		return "", err
	}
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(getRefreshDays()) * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func GenerateTokens(userID int64) (accessToken string, refreshToken string, err error) {
	accessToken, err = GenerateAccessToken(userID)
	if err != nil {
		return "", "", err
	}
	refreshToken, err = GenerateRefreshToken(userID)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

func ParseToken(tokenString string) (*Claims, int64, error) {
	secret, err := getSecret()
	if err != nil {
		return nil, 0, err
	}
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return nil, 0, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, claims.UserID, nil
	}
	return nil, 0, errors.New("invalid token claims")
}
