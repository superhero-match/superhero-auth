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
package cache

import (
	"github.com/superhero-match/superhero-auth/internal/cache/model"
	"time"
)

func(c *Cache) CreateAuth(userID string, td model.TokenDetails) error {
	at := time.Unix(td.AtExpires, 0)
	rt := time.Unix(td.RtExpires, 0)

	now := time.Now()

	errAccess := c.Redis.Set(td.AccessUuid, userID, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}

	errRefresh := c.Redis.Set(td.RefreshUuid, userID, rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}

	return nil
}