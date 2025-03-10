package security

import "github.com/golang-jwt/jwt/v5"

// VerifyToken verifies the JWT token and extracts the user ID.
func VerifyToken(tokenString, jwtSecret string) (string, bool) {
	if tokenString == "" {
		return "", false
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return "", false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if userID, exists := claims["id"].(string); exists {
			return userID, true
		}
	}
	return "", false
}

// GenerateToken creates a JWT token for a given user ID.
func GenerateToken(secret, userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id": userID,
	})
	return token.SignedString([]byte(secret))
}
