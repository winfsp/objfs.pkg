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
	"strings"

	"github.com/billziss-gh/golib/errors"
	"github.com/billziss-gh/objfs.pkg/auth/oauth2"
	"github.com/billziss-gh/objfs/auth"
	"github.com/billziss-gh/objfs/errno"
	"github.com/billziss-gh/objfs/httputil"
	"github.com/billziss-gh/objfs/objio"
)

type ioReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

type dropboxRequest struct {
	uri         *url.URL
	header      http.Header
	body        ioReadSeekCloser
	noBodyClose bool
}

type dropbox struct {
	rpcUri     *url.URL
	contentUri *url.URL
	session    auth.Session
	httpClient *http.Client
}

var errnomap = map[string]errno.Errno{
	"conflict":                  errno.EEXIST,
	"disallowed_name":           errno.EPERM,
	"insufficient_space":        errno.ENOSPC,
	"invalid_access_token":      errno.EACCES,
	"invalid_account_type":      errno.EACCES,
	"invalid_select_admin":      errno.EACCES,
	"invalid_select_user":       errno.EACCES,
	"no_write_permission":       errno.EACCES,
	"not_file":                  errno.EISDIR,
	"not_folder":                errno.ENOTDIR,
	"not_found":                 errno.ENOENT,
	"paper_access_denied":       errno.EACCES,
	"restricted_content":        errno.EACCES,
	"team_folder":               errno.EPERM,
	"too_many_files":            errno.ENOSPC, //errno.EDQUOT,
	"too_many_requests":         errno.ENOSPC, //errno.EDQUOT,
	"too_many_write_operations": errno.ENOSPC, //errno.EDQUOT,
	"user_suspended":            errno.EACCES,
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

	req := &http.Request{
		Method:     "POST",
		URL:        dbr.uri,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
		Host:       dbr.uri.Host,
		Body:       dbr.body,
	}

	// change to "GET" to allow for "Range" header
	if strings.HasSuffix(req.URL.Path, "/files/download") {
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

		if strings.HasPrefix(rsp.Header.Get("Content-type"), "application/json") {
			var content struct {
				ErrorSummary string                 `json:"error_summary"`
				Error        map[string]interface{} `json:"error"`
			}

			err = json.NewDecoder(rsp.Body).Decode(&content)
			if nil != err {
				errmesg = fmt.Sprintf("HTTP %d", rsp.StatusCode)
			} else {
				errmesg = fmt.Sprintf("HTTP %d: %s", rsp.StatusCode,
					content.ErrorSummary)

				for errmap := content.Error; 0 < len(errmap); {
					tag, ok := errmap[".tag"].(string)
					if ok {
						if rc, ok := errnomap[tag]; ok {
							errcode = rc
							break
						}
					}

					e, ok := errmap[tag]
					errmap = nil
					if ok && ".tag" != tag {
						switch t := e.(type) {
						case map[string]interface{}:
							errmap = t
						case string:
							errmap = map[string]interface{}{".tag": t}
						}
					}
				}
			}
		} else {
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
