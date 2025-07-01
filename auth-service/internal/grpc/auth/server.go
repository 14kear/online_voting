package auth

import (
	"context"
	"errors"
	"github.com/14kear/online_voting/auth-service/internal/domain/models"
	"github.com/14kear/online_voting/auth-service/internal/services/auth"
	ssov1 "github.com/14kear/online_voting/protos/gen/go/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HANDLERS

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int) (accessToken string, refreshToken string, userID int64, err error)
	RegisterNewUser(
		ctx context.Context,
		email string,
		password string) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	RefreshTokens(
		ctx context.Context,
		refreshToken string,
		appID int,
	) (newAccessToken string, newRefreshToken string, err error)
	Logout(ctx context.Context, refreshToken string, appID int) (err error)
	ValidateToken(ctx context.Context, accessToken string, appID int) (int64, string, error)
	IsBlocked(ctx context.Context, userID int64) (bool, error)
	SetUserBlockStatus(ctx context.Context, userID int64, block bool, accessToken string, appID int) error
	GetUsers(ctx context.Context, accessToken string, appID int) ([]models.User, error)
	SetUserAdminStatus(ctx context.Context, userID int64, admin bool, accessToken string, appID int) error
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

const (
	emptyValue = 0
)

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if err := validateLogin(req); err != nil {
		return nil, err
	}

	accessToken, refreshToken, userID, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		if errors.Is(err, auth.ErrBlockedUser) {
			return nil, status.Error(codes.PermissionDenied, "user is blocked")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssov1.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserId:       userID}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if err := validateRegister(req); err != nil {
		return nil, err
	}

	userID, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &ssov1.RegisterResponse{UserId: userID}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if err := validateIsAdmin(req); err != nil {
		return nil, err
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &ssov1.IsAdminResponse{IsAdmin: isAdmin}, nil
}

func (s *serverAPI) RefreshTokens(ctx context.Context, req *ssov1.RefreshTokenRequest) (*ssov1.RefreshTokenResponse, error) {
	accessToken, refreshToken, err := s.auth.RefreshTokens(ctx, req.GetRefreshToken(), int(req.GetAppId()))
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired refresh token")
	}

	return &ssov1.RefreshTokenResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s *serverAPI) Logout(ctx context.Context, req *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {
	err := s.auth.Logout(ctx, req.GetRefreshToken(), int(req.GetAppId()))
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "user logged out")
	}

	return &ssov1.LogoutResponse{}, nil
}

func (s *serverAPI) ValidateToken(ctx context.Context, req *ssov1.ValidateTokenRequest) (*ssov1.ValidateTokenResponse, error) {
	userID, email, err := s.auth.ValidateToken(ctx, req.GetAccessToken(), int(req.GetAppId()))
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid access token")
	}

	return &ssov1.ValidateTokenResponse{UserId: userID, Email: email}, nil
}

func (s *serverAPI) IsBlocked(ctx context.Context, req *ssov1.IsBlockedRequest) (*ssov1.IsBlockedResponse, error) {
	if err := validateIsBlocked(req); err != nil {
		return nil, err
	}

	isBlocked, err := s.auth.IsBlocked(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &ssov1.IsBlockedResponse{IsBlocked: isBlocked}, nil
}

func (s *serverAPI) SetUserBlockStatus(ctx context.Context, req *ssov1.SetUserBlockStatusRequest) (*ssov1.SetUserBlockStatusResponse, error) {
	err := s.auth.SetUserBlockStatus(ctx, req.GetUserId(), req.GetBlock(), req.GetAccessToken(), int(req.GetAppId()))
	if err != nil {
		return &ssov1.SetUserBlockStatusResponse{
			Success: false,
			Message: "failed to update block status",
		}, err
	}

	return &ssov1.SetUserBlockStatusResponse{
		Success: true,
		Message: "status updated",
	}, nil
}

func (s *serverAPI) SetUserAdminStatus(ctx context.Context, req *ssov1.SetAdminStatusRequest) (*ssov1.SetAdminStatusResponse, error) {
	err := s.auth.SetUserAdminStatus(ctx, req.GetUserId(), req.GetAdmin(), req.GetAccessToken(), int(req.GetAppId()))
	if err != nil {
		return &ssov1.SetAdminStatusResponse{
			Success: false,
			Message: "failed to switch user role",
		}, err
	}

	return &ssov1.SetAdminStatusResponse{
		Success: true,
		Message: "status updated",
	}, nil
}

func (s *serverAPI) GetUsers(ctx context.Context, req *ssov1.GetUsersRequest) (*ssov1.GetUsersResponse, error) {
	users, err := s.auth.GetUsers(ctx, req.GetAccessToken(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	var protoUsers []*ssov1.User
	for _, u := range users {
		protoUsers = append(protoUsers, &ssov1.User{
			Id:        u.ID,
			Email:     u.Email,
			IsBlocked: u.IsBlocked,
			IsAdmin:   u.IsAdmin,
		})
	}

	return &ssov1.GetUsersResponse{Users: protoUsers}, nil
}

func validateLogin(req *ssov1.LoginRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}

	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, "app_id is required")
	}
	return nil
}

func validateRegister(req *ssov1.RegisterRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}

	return nil
}

func validateIsAdmin(req *ssov1.IsAdminRequest) error {
	if req.GetUserId() == emptyValue {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}

	return nil
}

func validateIsBlocked(req *ssov1.IsBlockedRequest) error {
	if req.GetUserId() == emptyValue {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}
	return nil
}
