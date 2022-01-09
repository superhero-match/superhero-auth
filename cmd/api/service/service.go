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
package service

import (
	"github.com/superhero-match/superhero-auth/internal/cache"
	"github.com/superhero-match/superhero-auth/internal/cache/model"
	"github.com/superhero-match/superhero-auth/internal/config"
	j "github.com/superhero-match/superhero-auth/internal/jwt"
	jm "github.com/superhero-match/superhero-auth/internal/jwt/model"
)

// Service interface defines service methods.
type Service interface {
	CreateAuth(userID string, td model.TokenDetails) error
	FetchAuth(authD *model.AccessDetails) (string, error)
	DeleteAuth(uuid string) (int64, error)
	CreateToken(userID string) (*jm.TokenDetails, error)
}

// service holds all the different services that are used when handling request.
type service struct {
	Cache cache.Cache
	JWT   j.JWT
}

// NewService creates value of type Service.
func NewService(cfg *config.Config) (Service, error) {
	c, err := cache.NewCache(cfg)
	if err != nil {
		return nil, err
	}

	return &service{
		Cache: c,
		JWT:   j.NewJWT(cfg),
	}, nil
}
