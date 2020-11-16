/*
  Copyright (C) 2019 - 2020 MWSOFT
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
package controller

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	am "github.com/superhero-match/superhero-auth/cmd/api/model"
	"github.com/superhero-match/superhero-auth/internal/cache/model"
	"go.uber.org/zap"
	"net/http"
	"time"
)

func (ctrl *Controller) RefreshToken(c *gin.Context) {
	var refreshToken am.RefreshToken

	if err := c.ShouldBindJSON(&refreshToken); err != nil {
		ctrl.Service.Logger.Error(
			"failed while mapping request data to token pair in Token RefreshToken",
			zap.String("err", err.Error()),
			zap.String("time", time.Now().UTC().Format(ctrl.Service.TimeFormat)),
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"status":       http.StatusInternalServerError,
			"accessToken":  "",
			"refreshToken": "",
		})

		return
	}

	// Verify the token.
	token, err := jwt.Parse(refreshToken.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(ctrl.Service.JWT.RefreshTokenSecret), nil
	})
	if err != nil {
		ctrl.Service.Logger.Error(
			"failed while verifying the token in Token RefreshToken",
			zap.String("err", err.Error()),
			zap.String("time", time.Now().UTC().Format(ctrl.Service.TimeFormat)),
		)

		c.JSON(http.StatusUnauthorized, gin.H{
			"status":       http.StatusUnauthorized,
			"accessToken":  "",
			"refreshToken": "",
		})

		return
	}

	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		ctrl.Service.Logger.Error(
			"failed while verifying the claims and token is not valid in Token RefreshToken",
			zap.String("time", time.Now().UTC().Format(ctrl.Service.TimeFormat)),
		)

		c.JSON(http.StatusUnauthorized, gin.H{
			"status":       http.StatusUnauthorized,
			"accessToken":  "",
			"refreshToken": "",
		})

		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		refreshUuid, ok := claims["refresh_uuid"].(string)
		if !ok {
			ctrl.Service.Logger.Error(
				"failed while retrieving refresh_token claim in Token RefreshToken",
				zap.String("time", time.Now().UTC().Format(ctrl.Service.TimeFormat)),
			)

			c.JSON(http.StatusInternalServerError, gin.H{
				"status":       http.StatusInternalServerError,
				"accessToken":  "",
				"refreshToken": "",
			})

			return
		}

		userID, ok := claims["user_id"].(string)
		if !ok {
			ctrl.Service.Logger.Error(
				"failed while retrieving user_id claim in Token RefreshToken",
				zap.String("time", time.Now().UTC().Format(ctrl.Service.TimeFormat)),
			)

			c.JSON(http.StatusInternalServerError, gin.H{
				"status":       http.StatusInternalServerError,
				"accessToken":  "",
				"refreshToken": "",
			})

			return
		}

		deleted, delErr := ctrl.Service.DeleteAuth(refreshUuid)
		if delErr != nil || deleted == 0 {
			ctrl.Service.Logger.Error(
				"failed while deleting current token in Token RefreshToken",
				zap.String("time", time.Now().UTC().Format(ctrl.Service.TimeFormat)),
			)

			c.JSON(http.StatusUnauthorized, gin.H{
				"status":       http.StatusUnauthorized,
				"accessToken":  "",
				"refreshToken": "",
			})

			return
		}

		ts, createErr := ctrl.Service.CreateToken(userID)
		if createErr != nil {
			ctrl.Service.Logger.Error(
				"failed while creating new token pair in Token RefreshToken",
				zap.String("err", createErr.Error()),
				zap.String("time", time.Now().UTC().Format(ctrl.Service.TimeFormat)),
			)

			c.JSON(http.StatusInternalServerError, gin.H{
				"status":       http.StatusInternalServerError,
				"accessToken":  "",
				"refreshToken": "",
			})

			return
		}

		saveErr := ctrl.Service.CreateAuth(userID, model.TokenDetails{
			AccessToken:  ts.AccessToken,
			RefreshToken: ts.RefreshToken,
			AccessUuid:   ts.AccessUuid,
			RefreshUuid:  ts.RefreshUuid,
			AtExpires:    ts.AtExpires,
			RtExpires:    ts.RtExpires,
		})
		if saveErr != nil {
			ctrl.Service.Logger.Error(
				"failed while saving new token pair in Token RefreshToken",
				zap.String("err", saveErr.Error()),
				zap.String("time", time.Now().UTC().Format(ctrl.Service.TimeFormat)),
			)

			c.JSON(http.StatusInternalServerError, gin.H{
				"status":       http.StatusInternalServerError,
				"accessToken":  "",
				"refreshToken": "",
			})

			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":       http.StatusOK,
			"accessToken":  ts.AccessToken,
			"refreshToken": ts.RefreshToken,
		})
	} else {
		ctrl.Service.Logger.Error(
			"failed while verifying the claims and token in Token RefreshToken",
			zap.String("time", time.Now().UTC().Format(ctrl.Service.TimeFormat)),
		)

		c.JSON(http.StatusUnauthorized, gin.H{
			"status":       http.StatusUnauthorized,
			"accessToken":  "",
			"refreshToken": "",
		})
	}
}