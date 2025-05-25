package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"github.com/14kear/forum-project/auth-service/internal/config"
	"github.com/14kear/forum-project/auth-service/internal/domain/models"
	"github.com/14kear/forum-project/auth-service/internal/lib/jwt"
	"github.com/14kear/forum-project/auth-service/internal/services/mocks"
	"github.com/14kear/forum-project/auth-service/internal/storage"
	"github.com/14kear/forum-project/auth-service/utils"
	jwtGo "github.com/golang-jwt/jwt/v5"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"os"
	"testing"
	"time"
)

func newTestAuth(
	ctrl *gomock.Controller,
	up *mocks.MockUserProvider,
	us *mocks.MockUserSaver,
	ts *mocks.MockTokenStorage,
	ap *mocks.MockAppProvider,
) *Auth {
	return NewAuth(utils.New(config.Load("../../../config/local.yaml").Env), us, up, ap, ts, time.Minute, time.Hour)
}

func mustHash(s string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return hash
}

func TestMain(m *testing.M) {
	// Устанавливаем CONFIG_PATH относительно корня проекта
	err := os.Setenv("CONFIG_PATH", "C:\\Users\\shini\\OneDrive\\Рабочий стол\\forum-project\\auth-service\\config\\local.yaml")
	if err != nil {
		return
	}

	os.Exit(m.Run())
}

func TestAuth_Login_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserProvider := mocks.NewMockUserProvider(ctrl)
	mockAppProvider := mocks.NewMockAppProvider(ctrl)
	mockTokenStorage := mocks.NewMockTokenStorage(ctrl)

	user := models.User{
		ID:       123,
		Email:    "test@test.com",
		PassHash: mustHash("test"),
	}

	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}

	mockUserProvider.EXPECT().User(gomock.Any(), user.Email).Return(user, nil)
	mockAppProvider.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)
	mockTokenStorage.EXPECT().SaveToken(gomock.Any(), user.ID, app.ID, gomock.Any(), gomock.Any()).Return(int64(1), nil)

	authTest := newTestAuth(ctrl, mockUserProvider, nil, mockTokenStorage, mockAppProvider)

	at, rt, uid, err := authTest.Login(context.Background(), user.Email, "test", app.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, at)
	assert.NotEmpty(t, rt)
	assert.Equal(t, user.ID, uid)
}

func TestAuth_Login_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	up := mocks.NewMockUserProvider(ctrl)
	up.EXPECT().User(gomock.Any(), "kaban@mail.ru").Return(models.User{}, storage.ErrUserNotFound)

	authTest := newTestAuth(ctrl, up, nil, nil, nil)

	_, _, _, err := authTest.Login(context.Background(), "kaban@mail.ru", "test", 1)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestAuth_Login_WrongPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := models.User{
		ID:       123,
		Email:    "test@test.com",
		PassHash: mustHash("test"),
	}

	up := mocks.NewMockUserProvider(ctrl)
	up.EXPECT().User(gomock.Any(), user.Email).Return(user, nil)

	authTest := newTestAuth(ctrl, up, nil, nil, nil)

	_, _, _, err := authTest.Login(context.Background(), user.Email, "wrong", 1)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestAuth_Login_AppError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := models.User{
		ID:       123,
		Email:    "test@test.com",
		PassHash: mustHash("test"),
	}

	up := mocks.NewMockUserProvider(ctrl)
	ap := mocks.NewMockAppProvider(ctrl)

	up.EXPECT().User(gomock.Any(), user.Email).Return(user, nil)
	ap.EXPECT().App(gomock.Any(), 123).Return(models.App{}, storage.ErrAppNotFound)

	authTest := newTestAuth(ctrl, up, nil, nil, ap)

	_, _, _, err := authTest.Login(context.Background(), user.Email, "test", 123)
	require.Error(t, err)
	assert.Contains(t, err.Error(), ErrAppNotFound.Error())
}

func TestAuth_Login_SaveTokenError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := models.User{
		ID:       123,
		Email:    "test@test.com",
		PassHash: mustHash("test"),
	}
	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}

	up := mocks.NewMockUserProvider(ctrl)
	ap := mocks.NewMockAppProvider(ctrl)
	ts := mocks.NewMockTokenStorage(ctrl)

	up.EXPECT().User(gomock.Any(), user.Email).Return(user, nil)
	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)
	ts.EXPECT().SaveToken(gomock.Any(), user.ID, app.ID, gomock.Any(), gomock.Any()).Return(int64(1), errors.New("save token error"))

	authTest := newTestAuth(ctrl, up, nil, ts, ap)

	_, _, _, err := authTest.Login(context.Background(), user.Email, "test", app.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save token error")
}

func TestAuth_Register_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	us := mocks.NewMockUserSaver(ctrl)
	us.EXPECT().SaveUser(gomock.Any(), "windows@mail.ru", gomock.Any()).Return(int64(111), nil)

	authTest := newTestAuth(ctrl, nil, us, nil, nil)

	uid, err := authTest.RegisterNewUser(context.Background(), "windows@mail.ru", "pass")
	require.NoError(t, err)
	assert.Equal(t, int64(111), uid)
}

func TestAuth_Register_UserExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	us := mocks.NewMockUserSaver(ctrl)
	us.EXPECT().SaveUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(0), storage.ErrUserAlreadyExists)

	authTest := newTestAuth(ctrl, nil, us, nil, nil)

	_, err := authTest.RegisterNewUser(context.Background(), "existing@mail.ru", "pass")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUserExists)
}

func TestAuth_Register_SaveError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	us := mocks.NewMockUserSaver(ctrl)
	us.EXPECT().SaveUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(int64(0), errors.New("save error"))

	authTest := newTestAuth(ctrl, nil, us, nil, nil)

	_, err := authTest.RegisterNewUser(context.Background(), "new@mail.ru", "pass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save error")
}

func TestAuth_IsAdmin_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	up := mocks.NewMockUserProvider(ctrl)
	up.EXPECT().IsAdmin(gomock.Any(), int64(1)).Return(true, nil)

	authTest := newTestAuth(ctrl, up, nil, nil, nil)

	ok, err := authTest.IsAdmin(context.Background(), int64(1))
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestAuth_IsAdmin_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	up := mocks.NewMockUserProvider(ctrl)
	up.EXPECT().IsAdmin(gomock.Any(), gomock.Any()).Return(false, storage.ErrUserNotFound)

	authTest := newTestAuth(ctrl, up, nil, nil, nil)

	ok, err := authTest.IsAdmin(context.Background(), int64(11))
	require.Error(t, err)
	assert.False(t, ok)
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestAuth_IsAdmin_Fail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	up := mocks.NewMockUserProvider(ctrl)
	up.EXPECT().IsAdmin(gomock.Any(), gomock.Any()).Return(false, errors.New("undefined error"))

	authTest := newTestAuth(ctrl, up, nil, nil, nil)
	ok, err := authTest.IsAdmin(context.Background(), int64(1))
	require.Error(t, err)
	assert.False(t, ok)
	assert.Contains(t, err.Error(), "undefined error")
}

func buildRefreshToken(user models.User, app models.App, ttl time.Duration) string {
	tokens, _ := jwt.NewTokenPair(user, app, time.Minute, ttl)
	return tokens.RefreshToken
}

func TestAuth_RefreshTokens_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := models.User{ID: 1, Email: "test@test.com", PassHash: mustHash("test")}
	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}

	refresh := buildRefreshToken(user, app, time.Hour)

	up := mocks.NewMockUserProvider(ctrl)
	ap := mocks.NewMockAppProvider(ctrl)
	ts := mocks.NewMockTokenStorage(ctrl)

	up.EXPECT().User(gomock.Any(), user.Email).Return(user, nil)
	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)
	ts.EXPECT().IsRefreshTokenValid(
		gomock.Any(), user.ID, app.ID, refresh).Return(true, nil)
	ts.EXPECT().DeleteRefreshToken(gomock.Any(), user.ID, app.ID, refresh).Return(nil)
	ts.EXPECT().SaveToken(gomock.Any(), user.ID, app.ID, gomock.Any(), gomock.Any()).Return(int64(228), nil)

	authTest := newTestAuth(ctrl, up, nil, ts, ap)

	at, rt, err := authTest.RefreshTokens(context.Background(), refresh, app.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, at)
	assert.NotEmpty(t, rt)
}

func TestAuth_RefreshTokens_BadType(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := models.User{ID: 1, Email: "test@test.com", PassHash: mustHash("test")}
	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}

	tp, _ := jwt.NewTokenPair(user, app, time.Minute, time.Hour)
	badRefresh := tp.AccessToken

	ap := mocks.NewMockAppProvider(ctrl)
	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)

	authTest := newTestAuth(ctrl, nil, nil, nil, ap)

	_, _, err := authTest.RefreshTokens(context.Background(), badRefresh, app.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token type")
}

func TestAuth_RefreshTokens_ExpiredTokenClaim(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := models.User{ID: 1, Email: "test@test.com", PassHash: mustHash("test")}
	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}

	refresh := buildRefreshToken(user, app, -time.Hour) // просроченный токен

	ap := mocks.NewMockAppProvider(ctrl)
	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)

	authTest := newTestAuth(ctrl, nil, nil, nil, ap)

	_, _, err := authTest.RefreshTokens(context.Background(), refresh, app.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")
}

func TestAuth_RefreshTokens_BadEmailClaim(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := models.User{Email: "test@test.com", PassHash: mustHash("test")}
	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}

	claims := jwtGo.MapClaims{
		"uid": user.ID,
		"typ": "refresh",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, claims)
	rt, err := token.SignedString([]byte(app.Secret))
	require.NoError(t, err)

	ap := mocks.NewMockAppProvider(ctrl)
	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)

	authTest := newTestAuth(ctrl, nil, nil, nil, ap)

	_, _, err = authTest.RefreshTokens(context.Background(), rt, app.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email claim missing or invalid")
}

func TestAuth_RefreshTokens_TokenInvalid(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := models.User{ID: 1, Email: "test@test.com", PassHash: mustHash("test")}
	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}
	refresh := buildRefreshToken(user, app, time.Hour)

	ap := mocks.NewMockAppProvider(ctrl)
	up := mocks.NewMockUserProvider(ctrl)
	ts := mocks.NewMockTokenStorage(ctrl)

	up.EXPECT().User(gomock.Any(), user.Email).Return(user, nil)
	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)
	ts.EXPECT().IsRefreshTokenValid(gomock.Any(), user.ID, app.ID, refresh).Return(false, errors.New("refresh token invalid"))

	authTest := newTestAuth(ctrl, up, nil, ts, ap)

	_, _, err := authTest.RefreshTokens(context.Background(), refresh, app.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token invalid")
}

func TestAuth_RefreshTokens_FailSaveTokens(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := models.User{Email: "test@test.com", PassHash: mustHash("test")}
	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}
	refresh := buildRefreshToken(user, app, time.Hour)

	ap := mocks.NewMockAppProvider(ctrl)
	up := mocks.NewMockUserProvider(ctrl)
	ts := mocks.NewMockTokenStorage(ctrl)

	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)
	up.EXPECT().User(gomock.Any(), user.Email).Return(user, nil)
	ts.EXPECT().IsRefreshTokenValid(
		gomock.Any(), user.ID, app.ID, refresh).Return(true, nil)
	ts.EXPECT().DeleteRefreshToken(gomock.Any(), user.ID, app.ID, refresh).Return(nil)
	ts.EXPECT().SaveToken(gomock.Any(), user.ID, app.ID, gomock.Any(), gomock.Any()).Return(int64(0), errors.New("failed to store new refresh token"))

	authTest := newTestAuth(ctrl, up, nil, ts, ap)

	_, _, err := authTest.RefreshTokens(context.Background(), refresh, app.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store new refresh token")
}

func TestAuth_Logout_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := models.User{Email: "test@test.com", PassHash: mustHash("test")}
	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}
	refresh := buildRefreshToken(user, app, time.Hour)

	ap := mocks.NewMockAppProvider(ctrl)
	up := mocks.NewMockUserProvider(ctrl)
	ts := mocks.NewMockTokenStorage(ctrl)

	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)
	up.EXPECT().User(gomock.Any(), user.Email).Return(user, nil)
	ts.EXPECT().IsRefreshTokenValid(gomock.Any(), user.ID, app.ID, refresh).Return(true, nil)
	ts.EXPECT().DeleteRefreshToken(gomock.Any(), user.ID, app.ID, refresh).Return(nil)

	authTest := newTestAuth(ctrl, up, nil, ts, ap)

	err := authTest.Logout(context.Background(), refresh, app.ID)
	require.NoError(t, err)
}

func TestAuth_Logout_InvalidToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// испорченный токен
	bad := "not.a.jwt"
	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}

	ap := mocks.NewMockAppProvider(ctrl)
	ap.EXPECT().App(gomock.Any(), 1).Return(app, nil)

	auth := newTestAuth(ctrl, nil, nil, nil, ap)

	err := auth.Logout(context.Background(), bad, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

func TestAuth_Logout_BadType(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}
	user := models.User{ID: 555, PassHash: mustHash("test")}
	tp, _ := jwt.NewTokenPair(user, app, time.Minute, time.Hour)
	badRefresh := tp.AccessToken

	ap := mocks.NewMockAppProvider(ctrl)
	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)

	authTest := newTestAuth(ctrl, nil, nil, nil, ap)

	err := authTest.Logout(context.Background(), badRefresh, app.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token type")
}

func TestAuth_ValidateToken_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}
	user := models.User{Email: "test@test.com", PassHash: mustHash("test"), ID: int64(50)}

	tokenPair, _ := jwt.NewTokenPair(user, app, time.Minute, time.Hour)
	at := tokenPair.AccessToken

	ap := mocks.NewMockAppProvider(ctrl)
	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)

	authTest := newTestAuth(ctrl, nil, nil, nil, ap)

	uid, email, err := authTest.ValidateToken(context.Background(), at, app.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(50), uid)
	assert.Equal(t, user.Email, email)
}

func TestAuth_ValidateToken_InvalidSigningMethod(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	app := models.App{ID: 1, Secret: "secret", Name: "test"}
	user := models.User{ID: 50, Email: "test@test.com", PassHash: mustHash("test")}

	// генерируем RSA‑ключ и RS256‑токен
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	claims := jwtGo.MapClaims{
		"uid":    user.ID,
		"email":  user.Email,
		"app_id": app.ID,
		"typ":    "access",
		"exp":    time.Now().Add(time.Minute).Unix(),
	}
	token := jwtGo.NewWithClaims(jwtGo.SigningMethodRS256, claims)

	at, err := token.SignedString(privKey)
	require.NoError(t, err)

	ap := mocks.NewMockAppProvider(ctrl)
	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)

	authTest := newTestAuth(ctrl, nil, nil, nil, ap)

	_, _, err = authTest.ValidateToken(context.Background(), at, app.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
}

func TestAuth_ValidateToken_TokenExpired(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}
	user := models.User{ID: 50, Email: "test@test.com", PassHash: mustHash("test")}

	tp, _ := jwt.NewTokenPair(user, app, -time.Hour, time.Hour)
	at := tp.AccessToken

	ap := mocks.NewMockAppProvider(ctrl)
	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)

	authTest := newTestAuth(ctrl, nil, nil, nil, ap)

	_, _, err := authTest.ValidateToken(context.Background(), at, app.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")
}

func TestAuth_ValidateToken_BadIDClaim(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}
	user := models.User{Email: "test@test.com", PassHash: mustHash("test")}

	claims := jwtGo.MapClaims{
		"email": user.Email,
		"typ":   "access",
		"exp":   time.Now().Add(time.Minute).Unix(),
	}
	token := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, claims)
	at, err := token.SignedString([]byte(app.Secret))
	require.NoError(t, err)

	ap := mocks.NewMockAppProvider(ctrl)
	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)

	auth := newTestAuth(ctrl, nil, nil, nil, ap)

	_, _, err = auth.ValidateToken(context.Background(), at, app.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "userID (uid) not found")
}

func TestAuth_ValidateToken_BadEmailClaim(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	app := models.App{ID: 1, Secret: "test-secret", Name: "test"}
	user := models.User{ID: 50, PassHash: mustHash("test")}

	claims := jwtGo.MapClaims{
		"uid": user.ID,
		"typ": "access",
		"exp": time.Now().Add(time.Minute).Unix(),
	}
	token := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, claims)
	at, err := token.SignedString([]byte(app.Secret))
	require.NoError(t, err)

	ap := mocks.NewMockAppProvider(ctrl)
	ap.EXPECT().App(gomock.Any(), app.ID).Return(app, nil)

	auth := newTestAuth(ctrl, nil, nil, nil, ap)

	_, _, err = auth.ValidateToken(context.Background(), at, app.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email claim missing or invalid")
}
