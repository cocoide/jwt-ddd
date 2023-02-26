package util

import (
	bcrypt "golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	  /*『bcrypt』でpasswordをハッシュ化*/
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
	  return "", err
	}
  
	return string(hashedPassword), nil
  }
  
  /*ハッシュ化されたpasswordと平文のpasswordを比較して
  一致する場合はnilを返す関数*/
  func CheckPassword(hashedPassword string, inputPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(inputPassword))
  }