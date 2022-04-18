package service

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type JWTService struct {
	key []byte
}

func (JWTService) New() *JWTService {
	jwtService := &JWTService{
		key: []byte("my_secret_key"),
	}
	return jwtService
}

type Claims struct {
	AgentId int64 `json:"agentId"`
	jwt.StandardClaims
}

func (jwtService JWTService) Encode(agentId int64, expirationInMinutes time.Duration) (string, error) {
	expirationTime := time.Now().Add(expirationInMinutes * time.Minute)
	claims := &Claims{}
	claims.AgentId = agentId
	if expirationInMinutes != 0 {
		claims.StandardClaims = jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtService.key)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (jwtService JWTService) Decode(token string) (*Claims, error) {
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtService.key, nil
	})
	if err != nil {
		return nil, err
	}
	if !tkn.Valid {
		return nil, errors.New("Token Invalido")
	}

	return claims, nil
}
