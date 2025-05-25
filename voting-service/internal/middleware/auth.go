package middleware

import (
	ssov1 "github.com/14kear/online_voting/protos/gen/go/auth"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
	"strings"
)

type AuthMiddleware struct {
	authClient ssov1.AuthClient
	appID      int
}

func NewAuthMiddleware(authClient ssov1.AuthClient, appID int) *AuthMiddleware {
	return &AuthMiddleware{authClient: authClient, appID: appID}
}

func (m *AuthMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Пропускаем auth-эндпоинты
		if strings.HasPrefix(c.Request.URL.Path, "/auth/") {
			c.Next()
			return
		}

		// CORS-заголовки для токенов
		c.Header("Access-Control-Expose-Headers", "X-New-Access-Token, X-New-Refresh-Token")

		accessToken := extractTokenFromHeader(c.GetHeader("Authorization"))
		refreshToken := c.GetHeader("X-Refresh-Token")

		if accessToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing access token"})
			return
		}

		ctx := c.Request.Context()
		resp, err := m.authClient.ValidateToken(ctx, &ssov1.ValidateTokenRequest{
			AccessToken: accessToken,
			AppId:       int32(m.appID),
		})

		// Если токен валиден - пропускаем запрос
		if err == nil {
			c.Set("userID", resp.GetUserId())
			c.Set("userEmail", resp.GetEmail())
			c.Next()
			return
		}

		// Если ошибка НЕ связана с истёкшим токеном - 401
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.Unauthenticated || refreshToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		// Пробуем обновить токены
		newTokens, err := m.authClient.RefreshTokens(ctx, &ssov1.RefreshTokenRequest{
			RefreshToken: refreshToken,
			AppId:        int32(m.appID),
		})

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token refresh failed"})
			return
		}

		newValidateResp, err := m.authClient.ValidateToken(ctx, &ssov1.ValidateTokenRequest{
			AccessToken: newTokens.AccessToken,
			AppId:       int32(m.appID),
		})

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token validation after refresh failed"})
			return
		}

		// Устанавливаем новые токены в заголовки ответа
		c.Header("X-New-Access-Token", newTokens.AccessToken)
		c.Header("X-New-Refresh-Token", newTokens.RefreshToken)

		// Обновляем токены в текущем запросе
		c.Request.Header.Set("Authorization", "Bearer "+newTokens.AccessToken)
		c.Request.Header.Set("X-Refresh-Token", newTokens.RefreshToken)
		c.Set("userID", newValidateResp.GetUserId())
		c.Set("userEmail", newValidateResp.GetEmail())

		// Пропускаем запрос дальше с новыми токенами
		c.Next()
	}
}

func extractTokenFromHeader(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}
	return parts[1]
}
