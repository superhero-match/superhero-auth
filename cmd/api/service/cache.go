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
	"github.com/superhero-match/superhero-auth/internal/cache/model"
)

// CreateAuth sets token and refresh token in cache.
func (srv *service) CreateAuth(userID string, td model.TokenDetails) error {
	return srv.Cache.CreateAuth(userID, td)
}

// FetchAuth fetches token from cache.
func (srv *service) FetchAuth(authD *model.AccessDetails) (string, error) {
	return srv.Cache.FetchAuth(authD)
}

// DeleteAuth deletes token from cache.
func (srv *service) DeleteAuth(uuid string) (int64, error) {
	return srv.Cache.DeleteAuth(uuid)
}
