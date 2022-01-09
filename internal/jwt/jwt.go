/*
  Copyright (C) 2019 - 2022 MWSOFT
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package jwt

import (
	"github.com/superhero-match/superhero-auth/internal/config"
	"github.com/superhero-match/superhero-auth/internal/jwt/model"
)

// JWT interface defines JWT methods.
type JWT interface {
	CreateToken(userID string) (*model.TokenDetails, error)
}

// jwt holds all the JWT data.
type jwt struct {
	AccessTokenSecret  string
	RefreshTokenSecret string
}

// NewJWT creates new JWT.
func NewJWT(cfg *config.Config) (j JWT) {
	return &jwt{
		AccessTokenSecret:  cfg.JWT.AccessTokenSecret,
		RefreshTokenSecret: cfg.JWT.RefreshTokenSecret,
	}
}
