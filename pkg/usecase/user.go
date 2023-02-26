package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/cocoide/jwt-ddd/pkg/domain/model"
	"github.com/cocoide/jwt-ddd/pkg/domain/repository"
	"github.com/cocoide/jwt-ddd/pkg/myerror"
	"github.com/cocoide/jwt-ddd/pkg/util"
)
type UseCase interface {
	Signup(c context.Context, username, email, password string) (*model.User, error)
	Login(c context.Context, email, password string) (string, *model.User, error)
  }
  
  type useCase struct {
	repository repository.Repository
	timeout    time.Duration
  }
  func NewUseCase(userRepo repository.Repository) UseCase {
	return &useCase{
	  repository: userRepo,
	  timeout:    time.Duration(2) * time.Second,
	}
  }
  
  func (uc *useCase) Signup(c context.Context, username, email, password string) (*model.User, error) {
	// タムアウトの設定
	ctx, cancel := context.WithTimeout(c, uc.timeout)
	defer cancel()
  
	exsitUser, err := uc.repository.GetUserByEmail(ctx, email)
  
	if err != nil {
	  return nil, &myerror.InternalServerError{Err: err}
	}
	//入力されたメールアドレスのユーザーが存在するのか判定
	if exsitUser.ID != 0 {
	  return nil, &myerror.BadRequestError{Err: errors.New("user already exists")}
	}
	// パスワードのハッシュ化
	hashedPassword, err := util.HashPassword(password)
	if err != nil {
	  return nil, &myerror.InternalServerError{Err: err}
	}
  
	u := &model.User{
	  Username: username,
	  Email:    email,
	  Password: hashedPassword,
	}
	
	//データベースにユーザーを保存
	user, err := uc.repository.CreateUser(ctx, u)
	if err != nil {
	  return nil, &myerror.InternalServerError{Err: err}
	}
  
	return user, nil
   }
   
   func (uc *useCase) Login(c context.Context, email, password string) (string, *model.User, error) {
	ctx, cancel := context.WithTimeout(c, uc.timeout)
	defer cancel()
 
	user, err := uc.repository.GetUserByEmail(ctx, email)
	if err != nil {
	  return "", nil, &myerror.InternalServerError{Err: err}
	}
	if user.ID == 0 {
	  return "", nil, &myerror.BadRequestError{Err: errors.New("user is not exist")}
	}
	 
	err = util.CheckPassword(user.Password, password)
	if err != nil {
	  return "", nil, &myerror.BadRequestError{Err: errors.New("password is incorrect")}
	}
 
	signedString, err := util.GenerateSignedString(user.ID, user.Username)
	if err != nil {
	  return "", nil, &myerror.InternalServerError{Err: err}
	}
 
	return signedString, user, nil
  }