package tests

import (
	ssov1 "github.com/14kear/forum-project/protos/gen/go/auth"
	"github.com/14kear/onlineVotingBackend/auth-service/tests/suite"
	"github.com/brianvoe/gofakeit/v7"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

const (
	emptyAppID     = 0
	appID          = 1
	appSecret      = "test-secret"
	passDefaultLen = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err) // ошибки нет, иначе тест падает
	assert.NotEmpty(t, respReg.GetUserId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)

	loginTime := time.Now()

	accessToken := respLogin.GetAccessToken()
	refreshToken := respLogin.GetRefreshToken()
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)

	accessTokenParsed, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)

	accessClaims, ok := accessTokenParsed.Claims.(jwt.MapClaims)
	assert.True(t, ok)

	assert.Equal(t, respReg.GetUserId(), int64(accessClaims["uid"].(float64)))
	assert.Equal(t, email, accessClaims["email"].(string))
	assert.Equal(t, appID, int(accessClaims["app_id"].(float64)))
	assert.Equal(t, "access", accessClaims["typ"])

	const deltaSeconds = 1 // точность до 1 секунды для проверки времени жизни токена

	assert.InDelta(t, loginTime.Add(st.Cfg.AccessTokenTTL).Unix(), accessClaims["exp"].(float64), deltaSeconds)

	// проверка refresh token`a
	refreshTokenParsed, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)

	refreshClaims, ok := refreshTokenParsed.Claims.(jwt.MapClaims)
	assert.True(t, ok)

	assert.Equal(t, respReg.GetUserId(), int64(refreshClaims["uid"].(float64)))
	assert.Equal(t, email, refreshClaims["email"].(string))
	assert.Equal(t, "refresh", refreshClaims["typ"])

	assert.InDelta(t, loginTime.Add(st.Cfg.RefreshTokenTTL).Unix(), refreshClaims["exp"].(float64), deltaSeconds)
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}

func TestRegisterLogin_DuplicatedRegistration(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()

	// Первая попытка должна быть успешной
	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	// Вторая попытка - неуспешна
	respReg, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.Error(t, err)
	assert.Empty(t, respReg.GetUserId())
	assert.ErrorContains(t, err, "user already exists")
}

// TestRegister_FailCases testing REGISTER handler
func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		expectedErr string
	}{
		{
			name:        "Register with Empty Password",
			email:       gofakeit.Email(),
			password:    "",
			expectedErr: "password is required",
		},
		{
			name:        "Register with Empty Email",
			email:       "",
			password:    randomFakePassword(),
			expectedErr: "email is required",
		},
		{
			name:        "Register with Both Empty",
			email:       "",
			password:    "",
			expectedErr: "email is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tt.email,
				Password: tt.password,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)

		})
	}
}

// TestLogin_FailCases testing LOGIN handler
func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		appID       int32
		expectedErr string
	}{
		{
			name:        "Login with Empty Password",
			email:       gofakeit.Email(),
			password:    "",
			appID:       appID,
			expectedErr: "password is required",
		},
		{
			name:        "Login with Empty Email",
			email:       "",
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "email is required",
		},
		{
			name:        "Login with Both Empty Email and Password",
			email:       "",
			password:    "",
			appID:       appID,
			expectedErr: "email is required",
		},
		{
			name:        "Login with Non-Matching Password",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "invalid email or password",
		},
		{
			name:        "Login without AppID",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       emptyAppID,
			expectedErr: "app_id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    gofakeit.Email(),
				Password: randomFakePassword(),
			})
			require.NoError(t, err)

			_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
				Email:    tt.email,
				Password: tt.password,
				AppId:    tt.appID,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestIsAdmin_Success(t *testing.T) {
	ctx, st := suite.New(t)

	//email := gofakeit.Email()
	//password := randomFakePassword()
	//
	//_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
	//	Email:    email,
	//	Password: password,
	//})
	//require.NoError(t, err)
	//
	//loginUser, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
	//	Email:    email,
	//	Password: password,
	//	AppId:    appID,
	//})
	//require.NoError(t, err)

	// проверка, что не админ
	userID := int64(86)
	isAdmin, err := st.AuthClient.IsAdmin(ctx, &ssov1.IsAdminRequest{
		UserId: userID,
	})
	require.NoError(t, err)
	assert.Equal(t, false, isAdmin.GetIsAdmin())

	// проверка, что админ
	userIsAdmin := int64(96)
	isAdmin, err = st.AuthClient.IsAdmin(ctx, &ssov1.IsAdminRequest{
		UserId: userIsAdmin,
	})
	require.NoError(t, err)
	assert.Equal(t, true, isAdmin.GetIsAdmin())
}

func TestIsAdmin_Fail(t *testing.T) {
	ctx, st := suite.New(t)

	// user not found
	userID := int64(77777)
	isAdmin, err := st.AuthClient.IsAdmin(ctx, &ssov1.IsAdminRequest{
		UserId: userID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
	assert.Equal(t, false, isAdmin.GetIsAdmin())

	// other error
	userID = 13337
	isAdmin, err = st.AuthClient.IsAdmin(ctx, &ssov1.IsAdminRequest{
		UserId: userID,
	})
	require.Error(t, err)
	assert.Equal(t, false, isAdmin.GetIsAdmin())
	assert.Contains(t, err.Error(), "user not found")

}

func TestRefreshTokens_Success(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)

	loginUser, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)

	refreshToken := loginUser.GetRefreshToken()

	refreshTokens, err := st.AuthClient.RefreshTokens(ctx, &ssov1.RefreshTokenRequest{
		RefreshToken: refreshToken,
		AppId:        appID,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, refreshTokens.AccessToken)
	assert.NotEmpty(t, refreshTokens.RefreshToken)
}

func TestRefreshTokens_InvalidAppId(t *testing.T) {
	ctx, st := suite.New(t)

	appId := 1337
	email := gofakeit.Email()
	password := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)

	loginUser, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)

	_, err = st.AuthClient.RefreshTokens(ctx, &ssov1.RefreshTokenRequest{
		RefreshToken: loginUser.GetRefreshToken(),
		AppId:        int32(appId),
	})
	require.Error(t, err)
}

func TestRefreshTokens_InvalidToken(t *testing.T) {
	ctx, st := suite.New(t)

	_, err := st.AuthClient.RefreshTokens(ctx, &ssov1.RefreshTokenRequest{
		RefreshToken: "some.invalid.token",
		AppId:        appID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired refresh token")
}

func TestRefreshTokens_InvalidTokenType(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)

	loginUser, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)

	// Пытаемся обновить используя access token
	_, err = st.AuthClient.RefreshTokens(ctx, &ssov1.RefreshTokenRequest{
		RefreshToken: loginUser.AccessToken,
		AppId:        appID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired refresh token")
}

func TestRefreshTokens_ExpiredRefreshToken(t *testing.T) {
	ctx, st := suite.New(t)

	expiredToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InJlZ2lzdGVyTmV3VXNlckBtYWlsLnJ1IiwiZXhwIjoxNzQ2Nzg2OTA2LCJ0eXAiOiJyZWZyZXNoIiwidWlkIjo1Mn0.gx_oLTFSCqlCS5kwbRgxpesMszV8HtW8G7221lXs12U"

	_, err := st.AuthClient.RefreshTokens(ctx, &ssov1.RefreshTokenRequest{
		RefreshToken: expiredToken,
		AppId:        appID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired refresh token")
}

func TestLogout_Success(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)

	loginUser, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)

	_, err = st.AuthClient.Logout(ctx, &ssov1.LogoutRequest{
		AppId:        appID,
		RefreshToken: loginUser.GetRefreshToken(),
	})
	require.NoError(t, err)
}

func TestLogout_InvalidToken(t *testing.T) {
	ctx, st := suite.New(t)

	_, err := st.AuthClient.Logout(ctx, &ssov1.LogoutRequest{
		RefreshToken: "invalid.token",
		AppId:        appID,
	})
	require.Error(t, err)
}

func TestLogout_RevokedRefreshToken(t *testing.T) {
	ctx, st := suite.New(t)

	revokedRefreshToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InJlZ2lzdGVyTmV3VXNlckBtYWlsLnJ1IiwiZXhwIjoxNzQ2Nzg2OTA2LCJ0eXAiOiJyZWZyZXNoIiwidWlkIjo1Mn0.gx_oLTFSCqlCS5kwbRgxpesMszV8HtW8G7221lXs12U"

	_, err := st.AuthClient.Logout(ctx, &ssov1.LogoutRequest{
		RefreshToken: revokedRefreshToken,
		AppId:        appID,
	})
	require.Error(t, err)
}

func TestLogout_InvalidTokenType(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)

	loginResp, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)

	_, err = st.AuthClient.Logout(ctx, &ssov1.LogoutRequest{
		RefreshToken: loginResp.AccessToken,
		AppId:        appID,
	})
	require.Error(t, err)
}

func TestLogout_UserNotFound(t *testing.T) {
	ctx, st := suite.New(t)

	refreshToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InJlZ2lzdGVyTmV2zXNlckBtYWlsLnJ1IiwiZXhwIjoxNzQ2Nzg2OTA2LCJ0eXAiOiJyZWZyZXNoIiwidWlkIjo1Mn0.gx_oLTFSCqlCS5kwbRgxpesMszV8HtW8G7221lXs12U"

	_, err := st.AuthClient.Logout(ctx, &ssov1.LogoutRequest{
		RefreshToken: refreshToken,
		AppId:        appID,
	})
	require.Error(t, err)
}

func TestValidateAccessToken_Success(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)

	loginResp, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)

	validating, err := st.AuthClient.ValidateToken(ctx, &ssov1.ValidateTokenRequest{
		AccessToken: loginResp.AccessToken,
		AppId:       appID,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, validating.GetEmail())
	assert.NotEmpty(t, validating.GetUserId())
}

func TestRefreshTokensToken_ExpiredToken(t *testing.T) {
	ctx, st := suite.New(t)

	expiredRefreshToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImxvaEBtYWlsLnJ1IiwiZXhwIjoxNzQ3MjAzNTgxLCJ0eXAiOiJyZWZyZXNoIiwidWlkIjo4M30.IqMl2MvEKfPWqx2M8KaXlXFclomG1STDkAOSPP01lgA"

	_, err := st.AuthClient.RefreshTokens(ctx, &ssov1.RefreshTokenRequest{
		RefreshToken: expiredRefreshToken,
		AppId:        appID,
	})

	require.Error(t, err)
}

func TestValidateAccessToken_ExpiredToken(t *testing.T) {
	ctx, st := suite.New(t)

	expiredAccessToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHBfaWQiOjEsImVtYWlsIjoibG9oQG1haWwucnUiLCJleHAiOjE3NDY1OTk2ODEsInR5cCI6ImFjY2VzcyIsInVpZCI6ODN9.BPOAmK9u3y6rxXhGcBlam0wPexBqhoEU8V7TTLeevAQ"

	_, err := st.AuthClient.ValidateToken(ctx, &ssov1.ValidateTokenRequest{
		AccessToken: expiredAccessToken,
		AppId:       appID,
	})

	require.Error(t, err)
}

func TestValidateAccessToken_InvalidType(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)

	loginResp, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)

	_, err = st.AuthClient.ValidateToken(ctx, &ssov1.ValidateTokenRequest{
		AccessToken: loginResp.RefreshToken,
		AppId:       appID,
	})
	require.Error(t, err)
}

func TestValidateAccessToken_InvalidApp(t *testing.T) {
	ctx, st := suite.New(t)

	appId := 56

	email := gofakeit.Email()
	password := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)

	loginResp, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)

	_, err = st.AuthClient.ValidateToken(ctx, &ssov1.ValidateTokenRequest{
		AccessToken: loginResp.AccessToken,
		AppId:       int32(appId),
	})
	require.Error(t, err)
}

func TestValidateToken_InvalidFormat(t *testing.T) {
	ctx, st := suite.New(t)

	_, err := st.AuthClient.ValidateToken(ctx, &ssov1.ValidateTokenRequest{
		AccessToken: "bad.token.value",
		AppId:       appID,
	})
	require.Error(t, err)
}

//func TestConfigLoadViaEnv(t *testing.T) {
//	// Подготовка временного файла конфигурации
//	cfgPath := writeTempConfig(t)
//
//	// Устанавливаем переменную окружения CONFIG_PATH
//	os.Setenv("CONFIG_PATH", cfgPath)
//	defer os.Unsetenv("CONFIG_PATH")
//
//	// Сбрасываем глобальное состояние, если нужно
//	resetGlobals()
//
//	// Загружаем конфиг
//	cfg := config.MustLoad()
//
//	// Проверяем, что конфиг загрузился
//	require.NotNil(t, cfg)
//	assert.Equal(t, "/tmp/storage", cfg.StoragePath)
//}
//
//func resetGlobals() {
//	config.Parsed = false
//	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
//	os.Unsetenv("CONFIG_PATH")
//}
//
//func writeTempConfig(t *testing.T) string {
//	t.Helper()
//
//	content := `
//	env: "local"
//	storage_path: "/tmp/storage"
//	grpc:
//	  port: 50051
//	  timeout: 1s
//	http:
//	  port: 8080
//	access_ttl: 10m
//	refresh_ttl: 24h
//	`
//	tmp, err := os.CreateTemp(t.TempDir(), "cfg_*.yaml")
//	require.NoError(t, err)
//	_, err = tmp.WriteString(content)
//	require.NoError(t, err)
//	require.NoError(t, tmp.Close())
//
//	return tmp.Name()
//}
