package service

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestJWTService_DecodeWithSuccessfully(t *testing.T) {
	jwt := JWTService{}.New()
	claims, err := jwt.Decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZ2VudElkIjo5NDY2MjUsImNsaWVudElkIjozMjE3MywibXAiOiJbe1wibmFtZVwiOlwiTUFOQUdFTUVOVF9QQU5FTFwiLFwicmVzb3VyY2VzXCI6W3tcIm5hbWVcIjpcIkRBU0hCT0FSRFwiLFwicGVybWlzc2lvbnNcIjpbXCJBTExcIl19LHtcIm5hbWVcIjpcIkJJXCIsXCJwZXJtaXNzaW9uc1wiOltcIkFMTFwiXX1dfV0iLCJnZW5EYXRlIjoxNjQ5NzA0OTEzLCJpc3MiOiJ1bW92YXV0aCJ9.6tL3SWFiMX9X7JZsA6FrseaBOULIoVAgc48Hnd6qXy8")
	assert.Nil(t, err)
	assert.Equal(t, int64(946625), claims.AgentId)
}

func TestJWTService_DecodeWithTokenInvalidNumberSegments(t *testing.T) {
	jwt := JWTService{}.New()
	claims, err := jwt.Decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZ2VudElkIjo5NDY2MjUsImNsaWVudElkIjozMjE3MywibXAiOiJbe1")
	assert.Nil(t, claims)
	assert.Equal(t, "token contains an invalid number of segments", err.Error())

}

func TestJWTService_DecodeWithTokenInvalid(t *testing.T) {
	jwt := JWTService{}.New()
	claims, err := jwt.Decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZ2VudElkIjo5NDY2MjUsImNsaWVudElkIjozMjE3MywibXAiOiJbe1wibmFtZVwiOlwiTUFOQUdFTUVOVF9QQU5FTFwiLFwicmVzb3VyY2VzXCI6W3tcIm5hbWVcIjpcIkRBU0hCT0FSRFwiLFwicGVybWlzc2lvbnNcIjpbXCJBTExcIl19LHtcIm5hbWVcIjpcIkJJXCIsXCJwZXJtaXNzaW9uc1wiOltcIkFMTFwiXX1dfV0iLCJnZW5EYXRlIjoxNjQ5NzA0OTEzLCJpc3MiOiJ1bW92YXV0aCJ9.6tL3SWFiMX9X7JZsA6FrseaBOULIoVAgcxzcxzczxcxz")
	assert.Equal(t, "signature is invalid", err.Error())
	assert.Nil(t, claims)
}

func TestJWTService_EncodeWithSuccessfullyWithoutExpirationTime(t *testing.T) {
	jwt := JWTService{}.New()
	token, err := jwt.Encode(1212, 0)
	assert.Nil(t, err)
	assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2VudElkIjoxMjEyfQ.uk6SVBcL-YVQWQbVFzvDZU9siiuNXjJq1dcEL6HZPtc", token)
}

func TestJWTService_EncodeWithSuccessfullyWitExpirationTime(t *testing.T) {
	jwt := JWTService{}.New()
	token, err := jwt.Encode(1212, 2)
	assert.Nil(t, err)
	claims, err2 := jwt.Decode(token)
	assert.Nil(t, err2)
	assert.Equal(t, int64(1212), claims.AgentId)
	assert.NotNil(t, claims.StandardClaims.ExpiresAt)
}
