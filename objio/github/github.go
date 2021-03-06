/*
 * github.go
 *
 * Copyright 2018-2021 Bill Zissimopoulos
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

package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/billziss-gh/golib/errors"
	"github.com/billziss-gh/objfs.pkg/auth/oauth2"
	"github.com/billziss-gh/objfs/auth"
	"github.com/billziss-gh/objfs/errno"
	"github.com/billziss-gh/objfs/httputil"
	"github.com/billziss-gh/objfs/objio"
)

type githubStorageInfo struct {
}

func (self *githubStorageInfo) IsCaseInsensitive() bool {
	return false
}

func (self *githubStorageInfo) IsReadOnly() bool {
	return true
}

func (self *githubStorageInfo) MaxComponentLength() int {
	return 255 // !!!: just a guess!
}

func (self *githubStorageInfo) TotalSize() int64 {
	return 0
}

func (self *githubStorageInfo) FreeSize() int64 {
	return 0
}

type githubRepoInfo struct {
	FName  string    `json:"name"`
	FSize  int64     `json:"size"`
	FBtime time.Time `json:"created_at"`
	FMtime time.Time `json:"updated_at"`
}

func (info *githubRepoInfo) Name() string {
	return info.FName
}

func (info *githubRepoInfo) Size() int64 {
	return info.FSize
}

func (info *githubRepoInfo) Btime() time.Time {
	return info.FBtime
}

func (info *githubRepoInfo) Mtime() time.Time {
	return info.FMtime
}

func (info *githubRepoInfo) IsDir() bool {
	return true
}

func (info *githubRepoInfo) Sig() string {
	return ""
}

type githubRefInfo struct {
	FName   string `json:"name"`
	FCommit struct {
		FSig string `json:"sha"`
	} `json:"commit"`
}

func (info *githubRefInfo) Name() string {
	return info.FName
}

func (info *githubRefInfo) Size() int64 {
	return 0
}

func (info *githubRefInfo) Btime() time.Time {
	return time.Now().UTC()
}

func (info *githubRefInfo) Mtime() time.Time {
	return time.Now().UTC()
}

func (info *githubRefInfo) IsDir() bool {
	return true
}

func (info *githubRefInfo) Sig() string {
	return info.FCommit.FSig
}

type githubObjectInfo struct {
	FType string `json:"type"`
	FName string `json:"name"`
	FSize int64  `json:"size"`
	FSig  string `json:"sha"`
}

func (info *githubObjectInfo) Name() string {
	return info.FName
}

func (info *githubObjectInfo) Size() int64 {
	return info.FSize
}

func (info *githubObjectInfo) Btime() time.Time {
	return time.Now().UTC()
}

func (info *githubObjectInfo) Mtime() time.Time {
	return time.Now().UTC()
}

func (info *githubObjectInfo) IsDir() bool {
	return "dir" == info.FType
}

func (info *githubObjectInfo) Sig() string {
	return info.FSig
}

type ioReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

type githubRequest struct {
	method      string
	uri         *url.URL
	header      http.Header
	body        ioReadSeekCloser
	noBodyClose bool
}

type githubReader struct {
}

func (self *githubReader) Read(p []byte) (n int, err error) {
	return
}

func (self *githubReader) ReadAt(p []byte, off int64) (n int, err error) {
	return
}

func (self *githubReader) Close() (err error) {
	return
}

type github struct {
	apiUri     *url.URL
	session    auth.Session
	httpClient *http.Client
}

func (self *github) sendrecv(ghr *githubRequest, fn func(*http.Response) error) error {
	header := http.Header{}
	if nil != ghr.header {
		for k, v := range ghr.header {
			header[k] = v
		}
	}

	if nil != ghr.body && "" == header.Get("Content-type") {
		header.Add("Content-type", "application/json")
	}

	if "" == header.Get("Accept") {
		header.Add("Accept", "application/vnd.github.v3+json")
	}

	if nil != self.session {
		creds := self.session.Credentials()
		header.Add("Authorization", creds.Get("token_type")+" "+creds.Get("access_token"))
	}

	req := &http.Request{
		Method:     ghr.method,
		URL:        ghr.uri,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
		Host:       ghr.uri.Host,
		Body:       ghr.body,
	}

	rsp, err := httputil.Retry(ghr.body, func() (*http.Response, error) {
		return self.httpClient.Do(req)
	})
	if nil != err {
		return err
	}

	if 400 <= rsp.StatusCode {
		defer rsp.Body.Close()

		var content struct {
			Message string `json:"message"`
		}

		errmesg := ""
		errcode := errno.EIO
		err = json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			errmesg = fmt.Sprintf("HTTP %d", rsp.StatusCode)
		} else {
			errmesg = fmt.Sprintf("HTTP %d: %s", rsp.StatusCode,
				content.Message)
		}
		return errors.New(errmesg, err, errcode)
	}

	if !ghr.noBodyClose {
		defer rsp.Body.Close()
	}

	return fn(rsp)
}

func (self *github) Info(getsize bool) (info objio.StorageInfo, err error) {
	info = &githubStorageInfo{}
	return
}

func (self *github) listRepos(
	owner string, imarker string, maxcount int) (
	omarker string, infos []objio.ObjectInfo, err error) {

	if "" == imarker {
		imarker = "1"
	}
	if 0 == maxcount {
		maxcount = -1
	}

	const per_page = 100
	uri := *self.apiUri
	uri.Path = path.Join(uri.Path, fmt.Sprintf("/users/%s/repos", owner))
	uri.RawQuery = fmt.Sprintf("type=all&sort=full_name&per_page=%d&page=%s", per_page, imarker)

	ghr := githubRequest{
		method: "GET",
		uri:    &uri,
	}
	err = self.sendrecv(&ghr, func(rsp *http.Response) error {
		var content []*githubRepoInfo
		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}
		if per_page <= len(content) {
			m, _ := strconv.Atoi(imarker)
			omarker = strconv.Itoa(m + 1)
		}
		infos = make([]objio.ObjectInfo, len(content))
		i := 0
		for _, v := range content {
			if maxcount == i {
				omarker = ""
				break
			}
			infos[i] = v
			i++
		}
		infos = infos[:i]
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *github) listRefs(
	repo string, imarker string, maxcount int) (
	omarker string, infos []objio.ObjectInfo, err error) {

	if "" == imarker {
		imarker = "1"
	}
	if 0 == maxcount {
		maxcount = -1
	}

	const per_page = 100
	uri := *self.apiUri
	uri.Path = path.Join(uri.Path, fmt.Sprintf("/repos/%s/branches/", repo))
	uri.RawQuery = fmt.Sprintf("per_page=%d&page=%s", per_page, imarker)

	ghr := githubRequest{
		method: "GET",
		uri:    &uri,
	}
	err = self.sendrecv(&ghr, func(rsp *http.Response) error {
		var content []*githubRefInfo
		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}
		if per_page <= len(content) {
			m, _ := strconv.Atoi(imarker)
			omarker = strconv.Itoa(m + 1)
		}
		infos = make([]objio.ObjectInfo, len(content))
		i := 0
		for _, v := range content {
			if maxcount == i {
				omarker = ""
				break
			}
			infos[i] = v
			i++
		}
		infos = infos[:i]
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *github) listObjects(
	repo string, ref string, prefix string, imarker string, maxcount int) (
	omarker string, infos []objio.ObjectInfo, err error) {

	if 0 == maxcount {
		maxcount = -1
	}

	uri := *self.apiUri
	uri.Path = path.Join(uri.Path, fmt.Sprintf("/repos/%s/contents/%s", repo, prefix))
	uri.RawQuery = fmt.Sprintf("ref=%s", ref)

	header := http.Header{}
	header.Add("Accept", "application/vnd.github.v3.object")

	ghr := githubRequest{
		method: "GET",
		uri:    &uri,
		header: header,
	}
	err = self.sendrecv(&ghr, func(rsp *http.Response) error {
		var content struct {
			Infos []*githubObjectInfo `json:"entries"`
		}
		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}
		infos = make([]objio.ObjectInfo, len(content.Infos))
		i := 0
		for _, v := range content.Infos {
			if maxcount == i {
				break
			}
			infos[i] = v
			i++
		}
		infos = infos[:i]
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *github) List(
	prefix string, imarker string, maxcount int) (
	omarker string, infos []objio.ObjectInfo, err error) {

	comp := strings.Split(strings.TrimPrefix(prefix, "/"), "/")

	if 0 == len(comp) || (1 == len(comp) && "" == comp[0]) {
		// top level: do not list any users or repositories
		return
	} else if 1 == len(comp) {
		// user level: list all repos
		return self.listRepos(comp[0], imarker, maxcount)
	} else if 2 == len(comp) {
		// repo level: list all refs
		return self.listRefs(comp[0]+"/"+comp[1], imarker, maxcount)
	} else {
		// ref level: list files
		return self.listObjects(comp[0]+"/"+comp[1], comp[2], strings.Join(comp[3:], "/"), imarker, maxcount)
	}
}

func (self *github) Stat(name string) (info objio.ObjectInfo, err error) {
	return
}

func (self *github) Mkdir(prefix string) (info objio.ObjectInfo, err error) {
	err = errno.EROFS
	return
}

func (self *github) Rmdir(prefix string) (err error) {
	err = errno.EROFS
	return
}

func (self *github) Remove(name string) (err error) {
	err = errno.EROFS
	return
}

func (self *github) Rename(oldname string, newname string) (err error) {
	err = errno.EROFS
	return
}

func (self *github) OpenRead(
	name string, sig string) (
	info objio.ObjectInfo, reader io.ReadCloser, err error) {
	return
}

func (self *github) OpenWrite(name string, size int64) (writer objio.WriteWaiter, err error) {
	err = errno.EROFS
	return
}

// New creates an object that can access github storage.
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
		uristr = "https://api.github.com"
	}
	apiUri, err := url.Parse(uristr)
	if nil != err {
		return nil, errors.New(": invalid uri "+uristr, err, errno.EINVAL)
	}

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

	self := &github{
		apiUri:     apiUri,
		session:    session,
		httpClient: httpClient,
	}

	return self, nil
}

func NewAuth(args ...interface{}) (interface{}, error) {
	args = append(args,
		"https://github.com/login/oauth/authorize",
		"https://github.com/login/oauth/access_token")
	return auth.Registry.NewObject("oauth2", args...)
}

var _ objio.ObjectStorage = (*github)(nil)

// Load is used to ensure that this package is linked.
func Load() {
	oauth2.Load()
}

func init() {
	auth.Registry.RegisterFactory("github", NewAuth)
	objio.Registry.RegisterFactory("github", New)
}
