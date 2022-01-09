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
	"time"

	jw "github.com/dgrijalva/jwt-go"
	"github.com/twinj/uuid"

	"github.com/superhero-match/superhero-auth/internal/jwt/model"
)

// CreateToken create new JWT access and refresh tokens.
func (j *jwt) CreateToken(userID string) (*model.TokenDetails, error) {
	td := &model.TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = uuid.NewV4().String()

	var err error

	// Creating Access Token
	atClaims := jw.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = userID
	atClaims["exp"] = td.AtExpires

	at := jw.NewWithClaims(jw.SigningMethodHS256, atClaims)

	td.AccessToken, err = at.SignedString([]byte(j.AccessTokenSecret))
	if err != nil {
		return nil, err
	}

	// Creating Refresh Token
	rtClaims := jw.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = userID
	rtClaims["exp"] = td.RtExpires

	rt := jw.NewWithClaims(jw.SigningMethodHS256, rtClaims)

	td.RefreshToken, err = rt.SignedString([]byte(j.RefreshTokenSecret))
	if err != nil {
		return nil, err
	}

	return td, nil
}
