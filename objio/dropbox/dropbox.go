/*
 * dropbox.go
 *
 * Copyright 2018 Bill Zissimopoulos
 */
/*
 * This file is part of Objfs.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * Affero General Public License version 3 as published by the Free
 * Software Foundation.
 *
 * Licensees holding a valid commercial license may use this file in
 * accordance with the commercial license agreement provided with the
 * software.
 */

package dropbox

import (
	"io"

	"github.com/billziss-gh/objfs.pkg/auth/oauth2"
	"github.com/billziss-gh/objfs/auth"
	"github.com/billziss-gh/objfs/objio"
)

type dropbox struct {
}

func (self *dropbox) Info(getsize bool) (info objio.StorageInfo, err error) {
	return
}

func (self *dropbox) List(
	prefix string, imarker string, maxcount int) (
	omarker string, infos []objio.ObjectInfo, err error) {
	return
}

func (self *dropbox) Stat(name string) (info objio.ObjectInfo, err error) {
	return
}

func (self *dropbox) Mkdir(prefix string) (info objio.ObjectInfo, err error) {
	return
}

func (self *dropbox) Rmdir(prefix string) (err error) {
	return
}

func (self *dropbox) Remove(name string) (err error) {
	return
}

func (self *dropbox) Rename(oldname string, newname string) (err error) {
	return
}

func (self *dropbox) OpenRead(
	name string, sig string) (
	info objio.ObjectInfo, reader io.ReadCloser, err error) {
	return
}

func (self *dropbox) OpenWrite(name string, size int64) (writer objio.WriteWaiter, err error) {
	return
}

// New creates an object that can access dropbox storage.
func New(args ...interface{}) (interface{}, error) {
	return nil, nil
}

func NewAuth(args ...interface{}) (interface{}, error) {
	args = append(args,
		"https://www.dropbox.com/oauth2/authorize",
		"https://api.dropboxapi.com/oauth2/token")
	return auth.Registry.NewObject("oauth2", args...)
}

var _ objio.ObjectStorage = (*dropbox)(nil)

// Load is used to ensure that this package is linked.
func Load() {
	oauth2.Load()
}

func init() {
	auth.Registry.RegisterFactory("dropbox", NewAuth)
	objio.Registry.RegisterFactory("dropbox", New)
}
