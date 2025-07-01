package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/14kear/online_voting/auth-service/internal/domain/models"
	"github.com/14kear/online_voting/auth-service/internal/lib/jwt"
	"github.com/14kear/online_voting/auth-service/internal/storage"
	"github.com/14kear/sso-prettyslog/slogpretty/errors"
	jwtGo "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
	"time"
)

type Auth struct {
	log             *slog.Logger
	userSaver       UserSaver
	userProvider    UserProvider
	appProvider     AppProvider
	tokenStorage    TokenStorage
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

type TokenOperation struct {
	userID int64
	appID  int
	token  string
}

type TokenStorage interface {
	SaveToken(ctx context.Context, userID int64, appID int, token string, expiresAt time.Time) (int64, error)
	IsRefreshTokenValid(ctx context.Context, userID int64, appID int, token string) (bool, error)
	DeleteRefreshToken(ctx context.Context, userID int64, appID int, token string) error
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (user models.User, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	SetUserBlockStatus(ctx context.Context, userID int64, block bool) error
	IsBlocked(ctx context.Context, userID int64) (bool, error)
	GetUsers(ctx context.Context) ([]models.User, error)
	SetUserAdminStatus(ctx context.Context, userID int64, admin bool) error
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrBlockedUser        = errors.New("user is blocked")
)

// NewAuth return a new instance of the Auth service
func NewAuth(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenStorage TokenStorage,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:             log,
		userSaver:       userSaver,
		userProvider:    userProvider,
		appProvider:     appProvider,
		tokenStorage:    tokenStorage,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

// Login checks if user with given credentials exists in the system and returns access token.
// If user exists, but password is incorrect, returns error.
// If user doesn`t exist, returns error.
func (auth *Auth) Login(ctx context.Context, email, password string, appID int) (string, string, int64, error) {
	const op = "auth.Login"

	// БЕЗОПАСНОСТЬ! Мб вообще в будущем убрать логирование email
	log := auth.log.With(slog.String("op", op), slog.String("email", email))

	log.Info("attempting to login user")

	user, err := auth.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			auth.log.Warn("user not found", sl.Err(err))
			return "", "", 0, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		auth.log.Warn("failed to get user", sl.Err(err))
		return "", "", 0, fmt.Errorf("%s: %w", op, err)
	}

	if user.IsBlocked {
		return "", "", 0, fmt.Errorf("%s: %w", op, ErrBlockedUser)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		auth.log.Info("invalid credentials", sl.Err(err))
		return "", "", 0, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := auth.appProvider.App(ctx, appID)
	if err != nil {
		return "", "", 0, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("successfully logged in")

	tokenPair, err := jwt.NewTokenPair(user, app, auth.accessTokenTTL, auth.refreshTokenTTL)
	if err != nil {
		auth.log.Error("failed to generate token pair", sl.Err(err))
		return "", "", 0, fmt.Errorf("%s: %w", op, err)
	}

	refreshTokenSave, errTokenSave := auth.tokenStorage.SaveToken(ctx, user.ID, appID, tokenPair.RefreshToken, time.Now().Add(auth.refreshTokenTTL))
	if errTokenSave != nil {
		auth.log.Error("failed to save refresh token", sl.Err(errTokenSave))
		return "", "", 0, fmt.Errorf("%s: failed to store refresh token with id %d : %w", op, refreshTokenSave, errTokenSave)
	}

	return tokenPair.AccessToken, tokenPair.RefreshToken, user.ID, nil
}

// RegisterNewUser registers new user in the system and returns user ID.
// If user with given username already exists, returns error.
func (auth *Auth) RegisterNewUser(ctx context.Context, email string, pass string) (int64, error) {
	const op = "auth.RegisterNewUser"

	// не факт, что нужно логировать email, уточнить
	log := auth.log.With(slog.String("op", op), slog.String("email", email))

	log.Info("registering user")

	// хэш пароля + соль
	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate hash password", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := auth.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserAlreadyExists) {
			log.Warn("user already exists", sl.Err(err))
			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
		}
		log.Error("failed to save user", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered successfully")
	return id, nil
}

// IsAdmin checks if user is admin.
func (auth *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "auth.IsAdmin"

	log := auth.log.With(slog.String("op", op), slog.String("userID", fmt.Sprint(userID)))
	log.Info("checking if user is admin")

	isAdmin, err := auth.userProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return false, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("checking successfully", slog.Bool("isAdmin", isAdmin))
	return isAdmin, nil
}

func (auth *Auth) RefreshTokens(ctx context.Context, refreshToken string, appID int) (string, string, error) {
	const op = "auth.RefreshTokenTTL"

	log := auth.log.With(slog.String("op", op))
	log.Info("refreshing token")

	app, err := auth.appProvider.App(ctx, appID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	token, err := jwtGo.ParseWithClaims(refreshToken, jwtGo.MapClaims{}, func(token *jwtGo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtGo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(app.Secret), nil
	})
	if err != nil {
		return "", "", fmt.Errorf("%s: invalid token: %w", op, err)
	}

	claims, ok := token.Claims.(jwtGo.MapClaims)
	if !ok || !token.Valid {
		return "", "", fmt.Errorf("%s: invalid token claims", op)
	}

	if claims["typ"] != "refresh" {
		return "", "", fmt.Errorf("%s: invalid token type: expected refresh, got %v", op, claims["typ"])
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return "", "", fmt.Errorf("%s: exp claim is missing or invalid", op)
	}
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return "", "", fmt.Errorf("%s: refresh token is expired", op)
	}

	email, ok := claims["email"].(string)
	if !ok {
		log.Error("missing email in token claims", slog.Any("claims", claims))
		return "", "", fmt.Errorf("%s: email claim missing or invalid", op)
	}

	user, err := auth.userProvider.User(ctx, email)
	if err != nil {
		log.Error("user not found by email", slog.String("email", email), slog.Any("err", err))
		return "", "", fmt.Errorf("%s: failed to get user: %w", op, err)
	}
	valid, err := auth.tokenStorage.IsRefreshTokenValid(ctx, user.ID, appID, refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("%s: failed to validate refresh token: %w", op, err)
	}
	if !valid {
		return "", "", fmt.Errorf("%s: refresh token is not valid", op)
	}

	if err := auth.tokenStorage.DeleteRefreshToken(ctx, user.ID, appID, refreshToken); err != nil {
		auth.log.Warn("failed to delete refresh token", sl.Err(err))
	}

	newTokens, err := jwt.NewTokenPair(user, app, auth.accessTokenTTL, auth.refreshTokenTTL)
	if err != nil {
		return "", "", fmt.Errorf("%s: failed to generate token pair: %w", op, err)
	}

	if _, err := auth.tokenStorage.SaveToken(ctx, user.ID, appID, newTokens.RefreshToken, time.Now().Add(auth.refreshTokenTTL)); err != nil {
		log.Error("failed to save new refresh token", sl.Err(err))
		return "", "", fmt.Errorf("%s: failed to store new refresh token: %w", op, err)
	}

	log.Info("successfully refreshed tokens")

	return newTokens.AccessToken, newTokens.RefreshToken, nil
}

func (auth *Auth) Logout(ctx context.Context, refreshToken string, appID int) error {
	const op = "auth.Logout"

	log := auth.log.With(slog.String("op", op))
	log.Info("logout")

	app, err := auth.appProvider.App(ctx, appID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	token, err := jwtGo.ParseWithClaims(refreshToken, jwtGo.MapClaims{}, func(token *jwtGo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtGo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(app.Secret), nil
	})
	if err != nil {
		return fmt.Errorf("%s: invalid token: %w", op, err)
	}

	claims, ok := token.Claims.(jwtGo.MapClaims)
	if !ok || !token.Valid {
		return fmt.Errorf("%s: invalid token claims", op)
	}

	if claims["typ"] != "refresh" {
		return fmt.Errorf("%s: invalid token type: expected refresh, got %v", op, claims["typ"])
	}

	email, ok := claims["email"].(string)
	if !ok {
		return fmt.Errorf("%s: email claim missing or invalid", op)
	}

	user, err := auth.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			auth.log.Warn("user not found", sl.Err(err))
			return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		auth.log.Warn("failed to get user", sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	valid, err := auth.tokenStorage.IsRefreshTokenValid(ctx, user.ID, appID, refreshToken)
	if err != nil {
		return fmt.Errorf("%s: failed to validate refresh token: %w", op, err)
	}
	if !valid {
		return fmt.Errorf("%s: refresh token is not valid", op)
	}

	if err := auth.tokenStorage.DeleteRefreshToken(ctx, user.ID, appID, refreshToken); err != nil {
		auth.log.Warn("failed to delete refresh token", sl.Err(err))
	}

	log.Info("successfully logged out user")
	return nil
}

// ValidateToken валидирует access token! Валидация refresh token требует обращения к бд, поэтому реализована напрямую в RefreshTokens
func (auth *Auth) ValidateToken(ctx context.Context, accessToken string, appID int) (int64, string, error) {
	const op = "auth.ValidateToken"
	log := auth.log.With(slog.String("op", op))
	log.Info("validating token", slog.Int("appID", appID))

	app, err := auth.appProvider.App(ctx, appID)
	if err != nil {
		return 0, "", status.Errorf(codes.Internal, "%s: %v", op, err)
	}

	token, err := jwtGo.ParseWithClaims(accessToken, jwtGo.MapClaims{}, func(token *jwtGo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtGo.SigningMethodHMAC); !ok {
			return nil, status.Errorf(codes.Unauthenticated, "%s: unexpected signing method: %v", op, token.Header["alg"])
		}
		return []byte(app.Secret), nil
	})
	if err != nil {
		return 0, "", status.Errorf(codes.Unauthenticated, "%s: invalid token: %v", op, err)
	}

	claims, ok := token.Claims.(jwtGo.MapClaims)
	if !ok || !token.Valid {
		return 0, "", status.Error(codes.Unauthenticated, op+": invalid token claims")
	}

	if typ, ok := claims["typ"].(string); !ok || typ != "access" {
		return 0, "", status.Errorf(codes.Unauthenticated, "%s: invalid token type: expected access, got %v", op, claims["typ"])
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return 0, "", status.Errorf(codes.Unauthenticated, "%s: exp claim is missing or invalid", op)
	}
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return 0, "", status.Error(codes.Unauthenticated, op+": token is expired")
	}

	uidFloat, ok := claims["uid"].(float64)
	if !ok {
		return 0, "", status.Errorf(codes.Unauthenticated, "%s: userID (uid) not found or invalid in token", op)
	}
	uid := int64(uidFloat)

	email, ok := claims["email"].(string)
	if !ok {
		return 0, "", status.Errorf(codes.Unauthenticated, "%s: email claim missing or invalid", op)
	}

	log.Info("token validated successfully")
	return uid, email, nil
}

func (auth *Auth) SetUserBlockStatus(ctx context.Context, userID int64, block bool, accessToken string, appID int) error {
	const op = "auth.BlockUser"

	log := auth.log.With(slog.String("op", op))
	log.Info("blocking user")

	validatedID, _, err := auth.ValidateToken(ctx, accessToken, appID)
	if err != nil {
		return fmt.Errorf("%s: token invalid: %w", op, err)
	}

	isAdmin, err := auth.IsAdmin(ctx, validatedID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if !isAdmin {
		return fmt.Errorf("user %d is not an admin", validatedID)
	}

	err = auth.userProvider.SetUserBlockStatus(ctx, userID, block)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("blocked user")

	return nil
}

func (auth *Auth) SetUserAdminStatus(ctx context.Context, userID int64, admin bool, accessToken string, appID int) error {
	const op = "auth.SetUserAdminStatus"

	log := auth.log.With(slog.String("op", op))
	log.Info("switching user role")

	validatedID, _, err := auth.ValidateToken(ctx, accessToken, appID)
	if err != nil {
		return fmt.Errorf("%s: token invalid: %w", op, err)
	}

	isAdmin, err := auth.IsAdmin(ctx, validatedID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if !isAdmin {
		return fmt.Errorf("user %d is not an admin", validatedID)
	}

	err = auth.userProvider.SetUserAdminStatus(ctx, userID, admin)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user role switched")

	return nil
}

func (auth *Auth) IsBlocked(ctx context.Context, userID int64) (bool, error) {
	const op = "auth.isBlocked"

	log := auth.log.With(slog.String("op", op))
	log.Info("checking blocked user")

	isBlocked, err := auth.userProvider.IsBlocked(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return false, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("checking successfully", slog.Bool("isBlocked", isBlocked))
	return isBlocked, nil
}

func (auth *Auth) GetUsers(ctx context.Context, accessToken string, appID int) ([]models.User, error) {
	const op = "auth.GetUsers"

	log := auth.log.With(slog.String("op", op))
	log.Info("load users")

	validatedID, _, err := auth.ValidateToken(ctx, accessToken, appID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	isAdmin, err := auth.IsAdmin(ctx, validatedID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if !isAdmin {
		return nil, fmt.Errorf("user %d is not an admin", validatedID)
	}

	users, err := auth.userProvider.GetUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("loaded users")

	return users, nil
}
