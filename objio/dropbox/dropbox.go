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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/billziss-gh/golib/errors"
	"github.com/billziss-gh/objfs.pkg/auth/oauth2"
	"github.com/billziss-gh/objfs/auth"
	"github.com/billziss-gh/objfs/errno"
	"github.com/billziss-gh/objfs/httputil"
	"github.com/billziss-gh/objfs/objio"
)

type dropboxStorageInfo struct {
	totalSize uint64
	freeSize  uint64
}

func (self *dropboxStorageInfo) IsCaseInsensitive() bool {
	return true
}

func (self *dropboxStorageInfo) IsReadOnly() bool {
	return false
}

func (self *dropboxStorageInfo) MaxComponentLength() int {
	return 255 // !!!: just a guess!
}

func (self *dropboxStorageInfo) TotalSize() int64 {
	return int64(self.totalSize)
}

func (self *dropboxStorageInfo) FreeSize() int64 {
	return int64(self.freeSize)
}

type ioReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

type dropboxRequest struct {
	uri         *url.URL
	path        string
	header      http.Header
	body        ioReadSeekCloser
	noBodyClose bool
	apiError    interface{}
}

type dropbox struct {
	rpcUri     *url.URL
	contentUri *url.URL
	session    auth.Session
	httpClient *http.Client
}

func (self *dropbox) sendrecv(dbr *dropboxRequest, fn func(*http.Response) error) error {
	header := http.Header{}
	if nil != dbr.header {
		for k, v := range dbr.header {
			header[k] = v
		}
	}

	if nil != dbr.body && "" == header.Get("Content-type") {
		header.Add("Content-type", "application/json")
	}

	if nil != self.session {
		creds := self.session.Credentials()
		header.Add("Authorization", creds.Get("token_type")+" "+creds.Get("access_token"))
	}

	uri := *dbr.uri
	uri.Path = path.Join(uri.Path, dbr.path)
	req := &http.Request{
		Method:     "POST",
		URL:        &uri,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
		Host:       dbr.uri.Host,
		Body:       dbr.body,
	}

	// change to "GET" to allow for "Range" header
	if "/files/download" == dbr.path {
		req.Method = "GET"
	}

	rsp, err := httputil.Retry(dbr.body, func() (*http.Response, error) {
		return self.httpClient.Do(req)
	})
	if nil != err {
		return err
	}

	if 416 == rsp.StatusCode && "" != dbr.header.Get("Range") {
		// special case Range requests!
	} else if 400 <= rsp.StatusCode {
		defer rsp.Body.Close()

		errmesg := ""
		errcode := errno.EIO
		switch rsp.StatusCode {
		case 401, 403:
			errcode = errno.EACCES
		case 429:
			errcode = errno.ENOSPC //errno.EDQUOT
		case 409:
			if nil == dbr.apiError ||
				!strings.HasPrefix(rsp.Header.Get("Content-type"), "application/json") {
				break
			}

			err = json.NewDecoder(rsp.Body).Decode(dbr.apiError)
			if nil != err {
				break
			}

			if e, ok := dbr.apiError.(apiError); ok {
				errmesg = fmt.Sprintf("HTTP %d: %s", rsp.StatusCode, e.Message())
				errcode = e.Errno()
			}
		}

		if "" == errmesg {
			errmesg = fmt.Sprintf("HTTP %d", rsp.StatusCode)
		}

		return errors.New(errmesg, err, errcode)
	}

	if !dbr.noBodyClose {
		defer rsp.Body.Close()
	}

	return fn(rsp)
}

func (self *dropbox) Info(getsize bool) (info objio.StorageInfo, err error) {
	if !getsize {
		info = &dropboxStorageInfo{}
		return
	}

	dbr := dropboxRequest{
		uri:  self.rpcUri,
		path: "/users/get_space_usage",
	}
	err = self.sendrecv(&dbr, func(rsp *http.Response) error {
		var content spaceUsage

		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}

		stginfo := &dropboxStorageInfo{}
		if nil != content.Allocation {
			if nil != content.Allocation.Team {
				stginfo.totalSize = content.Allocation.Team.UserWithinTeamSpaceAllocated
				if 0 != stginfo.totalSize {
					stginfo.freeSize = stginfo.totalSize - content.Used
				} else {
					stginfo.totalSize = content.Allocation.Team.Allocated
					stginfo.freeSize = stginfo.totalSize - content.Allocation.Team.Used
				}
			} else if nil != content.Allocation.Individual {
				stginfo.totalSize = content.Allocation.Individual.Allocated
				stginfo.freeSize = stginfo.totalSize - content.Used
			} else if 0 != content.Allocation.Allocated {
				stginfo.totalSize = content.Allocation.Allocated
				stginfo.freeSize = stginfo.totalSize - content.Used
			}
		}

		info = stginfo
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

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
	var (
		uristr     string
		session    auth.Session
		creds      auth.CredentialMap
		httpClient = httputil.DefaultClient
	)

	for _, arg := range args {
		switch a := arg.(type) {
		case string:
			uristr = a
		case auth.Session:
			session = a
		case auth.CredentialMap:
			creds = a
		case *http.Client:
			httpClient = a
		}
	}

	if "" == uristr {
		uristr = "https://api.dropboxapi.com/2"
	}
	rpcUri, err := url.Parse(uristr)
	if nil != err {
		return nil, errors.New(": invalid uri "+uristr, err, errno.EINVAL)
	}

	contentUri := &url.URL{}
	*contentUri = *rpcUri
	contentUri.Host = strings.Replace(contentUri.Host,
		"api.dropboxapi.com", "content.dropboxapi.com", 1)

	if nil == session {
		if nil == creds {
			creds = auth.CredentialMap{}
		}
		a, err := NewAuth(httpClient)
		if nil != err {
			return nil, errors.New("", err, errno.EACCES)
		}
		s, err := a.(auth.Auth).Session(creds)
		if nil != err {
			return nil, errors.New("", err, errno.EACCES)
		}
		session = s
	}

	self := &dropbox{
		rpcUri:     rpcUri,
		contentUri: contentUri,
		session:    session,
		httpClient: httpClient,
	}

	return self, nil
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
