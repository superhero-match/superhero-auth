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
package controller

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/superhero-match/superhero-auth/cmd/api/model"
	cm "github.com/superhero-match/superhero-auth/internal/cache/model"
)

func (ctrl *Controller) Token(c *gin.Context) {
	var user model.User

	if err := c.ShouldBindJSON(&user); err != nil {
		ctrl.Logger.Error(
			"failed while binding request data to API model User in Token handler",
			zap.String("err", err.Error()),
			zap.String("time", time.Now().UTC().Format(ctrl.TimeFormat)),
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"status":       http.StatusInternalServerError,
			"accessToken":  "",
			"refreshToken": "",
		})

		return
	}

	token, err := ctrl.Service.CreateToken(user.ID)
	if err != nil {
		ctrl.Logger.Error(
			"failed while creating token pair in Token handler",
			zap.String("err", err.Error()),
			zap.String("time", time.Now().UTC().Format(ctrl.TimeFormat)),
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"status":       http.StatusInternalServerError,
			"accessToken":  "",
			"refreshToken": "",
		})

		return
	}

	saveErr := ctrl.Service.CreateAuth(user.ID, cm.TokenDetails{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		AccessUuid:   token.AccessUuid,
		RefreshUuid:  token.RefreshUuid,
		AtExpires:    token.AtExpires,
		RtExpires:    token.RtExpires,
	})
	if saveErr != nil {
		ctrl.Logger.Error(
			"failed while saving token pair in Token handler",
			zap.String("err", saveErr.Error()),
			zap.String("time", time.Now().UTC().Format(ctrl.TimeFormat)),
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
		"accessToken":  token.AccessToken,
		"refreshToken": token.RefreshToken,
	})
}
