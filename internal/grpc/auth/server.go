package auth

import (
	"context"
	"errors"
	"github.com/sol1corejz/auth-service/internal/services/auth"
	ssov1 "github.com/sol1corejz/sso-protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(ctx context.Context, email string, password string, appID int) (acessToken string, refreshToken string, err error)
	RegisterNewUser(ctx context.Context, email string, password string) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	CheckAndRefreshTokens(ctx context.Context, accessToken string, refreshToken string) (bool, string, error)
}

type ServerAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &ServerAPI{auth: auth})
}

const (
	emptyVlaue = 0
)

func (s *ServerAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {

	if err := validateLogin(req); err != nil {
		return nil, err
	}

	accessToken, refreshToken, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *ServerAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if err := validateRegister(req); err != nil {
		return nil, err
	}

	userID, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RegisterResponse{
		UserId: userID,
	}, nil
}

func (s *ServerAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if err := validateIsAdmin(req); err != nil {
		return nil, err
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

func (s *ServerAPI) CheckAndRefreshTokens(ctx context.Context, req *ssov1.TokenCheckRequest) (*ssov1.TokenCheckResponse, error) {
	if err := validateTokens(req); err != nil {
		return &ssov1.TokenCheckResponse{
			IsValid:        false,
			NewAccessToken: "",
		}, err
	}

	isValid, newAccessToken, err := s.auth.CheckAndRefreshTokens(ctx, req.GetAccessToken(), req.GetRefreshToken())
	if err != nil {
		return &ssov1.TokenCheckResponse{
			IsValid:        false,
			NewAccessToken: "",
		}, err
	}

	return &ssov1.TokenCheckResponse{
		IsValid:        isValid,
		NewAccessToken: newAccessToken,
	}, err
}

func validateLogin(req *ssov1.LoginRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email required")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password required")
	}

	if req.GetAppId() == emptyVlaue {
		return status.Error(codes.InvalidArgument, "app id required")
	}

	return nil
}

func validateRegister(req *ssov1.RegisterRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email required")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password required")
	}

	return nil
}

func validateIsAdmin(req *ssov1.IsAdminRequest) error {
	if req.GetUserId() == emptyVlaue {
		return status.Error(codes.InvalidArgument, "user_id required")
	}

	return nil
}

func validateTokens(req *ssov1.TokenCheckRequest) error {
	if req.GetAccessToken() == "" {
		return status.Error(codes.InvalidArgument, "access_token required")
	}

	if req.GetRefreshToken() == "" {
		return status.Error(codes.InvalidArgument, "refresh_token required")
	}

	return nil

}
