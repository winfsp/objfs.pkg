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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/billziss-gh/golib/errors"
	"github.com/billziss-gh/objfs.pkg/auth/oauth2"
	"github.com/billziss-gh/objfs/auth"
	"github.com/billziss-gh/objfs/errno"
	"github.com/billziss-gh/objfs/httputil"
	"github.com/billziss-gh/objfs/objio"
)

var dropboxStartTime = time.Now()

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

type dropboxObjectInfo struct {
	Tag          string       `json:".tag"`
	FName        string       `json:"name"`            // files and folders
	FMtime       time.Time    `json:"server_modified"` // files only
	FRev         string       `json:"rev"`             // files only
	FSize        uint64       `json:"size"`            // files only
	FSymlinkInfo *symlinkInfo `json:"symlink_info"`    // files only
	FSharingInfo *sharingInfo `json:"sharing_info"`    // files and folders
}

func (info *dropboxObjectInfo) Name() string {
	if "" == info.FName {
		return "/"
	}
	return info.FName
}

func (info *dropboxObjectInfo) Size() int64 {
	return int64(info.FSize)
}

func (info *dropboxObjectInfo) Btime() time.Time {
	return info.Mtime()
}

func (info *dropboxObjectInfo) Mtime() time.Time {
	if info.IsDir() {
		return dropboxStartTime
	}
	return info.FMtime
}

func (info *dropboxObjectInfo) IsDir() bool {
	return "folder" == info.Tag
}

func (info *dropboxObjectInfo) Sig() string {
	if info.IsDir() {
		return ""
	}
	return fmt.Sprintf("W/\"%s\"", info.FRev)
}

type ioReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

type dropboxRequestBody struct {
	*bytes.Reader
}

func (*dropboxRequestBody) Close() error {
	return nil
}

func requestBody(buf *bytes.Buffer) ioReadSeekCloser {
	return &dropboxRequestBody{bytes.NewReader(buf.Bytes())}
}

func filePath(p string) string {
	if "/" == p {
		return ""
	}

	return path.Join("/", p)
}

type dropboxRequest struct {
	uri         *url.URL
	path        string
	header      http.Header
	body        ioReadSeekCloser
	noBodyClose bool
	apiError    interface{}
}

const fragmentSize = 4 * 320 * 1024 // onedrive's base upload fragment size is 320KiB

type dropboxWriter struct {
	owner     *dropbox
	name      string
	size      int64
	off       int64
	sessionId string
	body      bytes.Buffer
	info      objio.ObjectInfo
	mux       sync.Mutex
}

func (self *dropboxWriter) uploadSmall() (err error) {
	endoff := self.off + int64(self.body.Len())

	var content = commitInfo{
		filePath(self.name),
		"overwrite",
	}

	arg, err := json.Marshal(&content)
	if nil != err {
		err = errors.New("", err, errno.EIO)
		return
	}

	header := http.Header{}
	header.Add("Content-type", "application/octet-stream")
	header.Add("Dropbox-API-Arg", string(arg))

	dbr := dropboxRequest{
		uri:      self.owner.contentUri,
		path:     "/files/upload",
		header:   header,
		body:     requestBody(&self.body),
		apiError: &uploadApiError{},
	}
	err = self.owner.sendrecv(&dbr, func(rsp *http.Response) error {
		if 200 != rsp.StatusCode {
			return errors.New("bad HTTP status", nil, errno.EIO)
		}

		var content dropboxObjectInfo
		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}

		content.Tag = "file"
		self.info = &content
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
		return
	}

	self.off = endoff
	self.body.Reset()
	return
}

func (self *dropboxWriter) uploadLarge() (err error) {
	endoff := self.off + int64(self.body.Len())

	var state string
	var content uploadSessionArg
	var apiError interface{}

	if "" == self.sessionId {
		state = "start"
		apiError = nil
	} else if endoff < self.size {
		state = "append_v2"
		apiError = &uploadSessionAppendApiError{}
		content.Cursor = &uploadSessionCursor{
			self.sessionId,
			uint64(self.off),
		}
	} else {
		state = "finish"
		apiError = &uploadSessionFinishApiError{}
		content.Cursor = &uploadSessionCursor{
			self.sessionId,
			uint64(self.off),
		}
		content.Commit = &commitInfo{
			filePath(self.name),
			"overwrite",
		}
	}

	arg, err := json.Marshal(&content)
	if nil != err {
		err = errors.New("", err, errno.EIO)
		return
	}

	header := http.Header{}
	header.Add("Content-type", "application/octet-stream")
	header.Add("Dropbox-API-Arg", string(arg))

	dbr := dropboxRequest{
		uri:      self.owner.contentUri,
		path:     "/files/upload_session/" + state,
		header:   header,
		body:     requestBody(&self.body),
		apiError: apiError,
	}
	err = self.owner.sendrecv(&dbr, func(rsp *http.Response) error {
		if 200 != rsp.StatusCode {
			return errors.New("bad HTTP status", nil, errno.EIO)
		}

		switch state {
		case "start":
			var content struct {
				SessionId string `json:"session_id"`
			}
			err := json.NewDecoder(rsp.Body).Decode(&content)
			if nil != err {
				return err
			}
			if "" == content.SessionId {
				return errors.New("bad session id", nil, errno.EIO)
			}
			self.sessionId = content.SessionId
		case "append_v2":
		case "finish":
			var content dropboxObjectInfo
			err := json.NewDecoder(rsp.Body).Decode(&content)
			if nil != err {
				return err
			}
			content.Tag = "file"
			self.info = &content
		default:
			panic("unknown state " + state)
		}

		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
		return
	}

	self.off = endoff
	self.body.Reset()
	return
}

func (self *dropboxWriter) Write(p []byte) (written int, err error) {
	self.mux.Lock()
	defer self.mux.Unlock()

	for 0 != len(p) {
		n := fragmentSize - self.body.Len()
		if n > len(p) {
			n = len(p)
		}

		self.body.Write(p[:n]) // bytes.(*Buffer).Write cannot fail
		p = p[n:]

		if fragmentSize == self.body.Len() && (0 != len(p) || "" != self.sessionId) {
			err = self.uploadLarge()
			if nil != err {
				return
			}
		}

		written += n
	}

	return
}

func (self *dropboxWriter) Close() (err error) {
	self.mux.Lock()
	defer self.mux.Unlock()

	self.sessionId = ""
	self.off = 0
	self.body.Reset()
	return nil
}

func (self *dropboxWriter) Wait() (info objio.ObjectInfo, err error) {
	self.mux.Lock()
	defer self.mux.Unlock()

	if "" != self.sessionId {
		if 0 != self.body.Len() {
			err = self.uploadLarge()
		}
	} else {
		err = self.uploadSmall()
	}

	if nil == err {
		info = self.info
	}

	return
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

	method := "POST"
	if "/files/download" == dbr.path && "" != header.Get("Range") {
		// change to "GET" to allow for "Range" header
		method = "GET"
	}

	uri := *dbr.uri
	uri.Path = path.Join(uri.Path, dbr.path)
	req := &http.Request{
		Method:     method,
		URL:        &uri,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
		Host:       dbr.uri.Host,
		Body:       dbr.body,
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

	var path string
	var body bytes.Buffer
	var apiError interface{}

	if "" == imarker {
		path = "/files/list_folder"
		apiError = &listFolderApiError{}

		var content = struct {
			Path  string `json:"path"`
			Limit uint32 `json:"limit,omitempty"`
		}{
			filePath(prefix),
			0,
		}

		if 0 < maxcount {
			content.Limit = uint32(maxcount)
		} else {
			maxcount = -1
		}

		err = json.NewEncoder(&body).Encode(&content)
		if nil != err {
			err = errors.New("", err, errno.EIO)
			return
		}
	} else {
		path = "/files/list_folder/continue"
		apiError = &listFolderContinueApiError{}
		maxcount = -1

		var content = struct {
			Cursor string `json:"cursor"`
		}{
			imarker,
		}

		err = json.NewEncoder(&body).Encode(&content)
		if nil != err {
			err = errors.New("", err, errno.EIO)
			return
		}
	}

	dbr := dropboxRequest{
		uri:      self.rpcUri,
		path:     path,
		body:     requestBody(&body),
		apiError: apiError,
	}
	err = self.sendrecv(&dbr, func(rsp *http.Response) error {
		var content listFolderResult
		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}
		if content.HasMore {
			omarker = content.Cursor
		}
		infos = make([]objio.ObjectInfo, len(content.Entries))
		i := 0
		for _, v := range content.Entries {
			if maxcount == i {
				break
			}
			if "file" != v.Tag && "folder" != v.Tag {
				continue
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

func (self *dropbox) Stat(name string) (info objio.ObjectInfo, err error) {
	var content = struct {
		Path string `json:"path"`
	}{
		filePath(name),
	}

	var body bytes.Buffer
	err = json.NewEncoder(&body).Encode(&content)
	if nil != err {
		err = errors.New("", err, errno.EIO)
		return
	}

	dbr := dropboxRequest{
		uri:      self.rpcUri,
		path:     "/files/get_metadata",
		body:     requestBody(&body),
		apiError: &getMetadataApiError{},
	}
	err = self.sendrecv(&dbr, func(rsp *http.Response) error {
		var content dropboxObjectInfo
		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}
		info = &content
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *dropbox) Mkdir(prefix string) (info objio.ObjectInfo, err error) {
	var content = struct {
		Path string `json:"path"`
	}{
		filePath(prefix),
	}

	var body bytes.Buffer
	err = json.NewEncoder(&body).Encode(&content)
	if nil != err {
		err = errors.New("", err, errno.EIO)
		return
	}

	dbr := dropboxRequest{
		uri:      self.rpcUri,
		path:     "/files/create_folder_v2",
		body:     requestBody(&body),
		apiError: &createFolderV2ApiError{},
	}
	err = self.sendrecv(&dbr, func(rsp *http.Response) error {
		var content createFolderResult
		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}
		if nil == content.Metadata {
			_, name := path.Split(prefix)
			content.Metadata = &dropboxObjectInfo{
				FName: name,
			}
		}
		content.Metadata.Tag = "folder"
		info = content.Metadata
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *dropbox) Rmdir(prefix string) (err error) {
	return self.remove(prefix, true)
}

func (self *dropbox) Remove(name string) (err error) {
	return self.remove(name, false)
}

func (self *dropbox) remove(name string, dir bool) (err error) {
	var content = struct {
		Path string `json:"path"`
	}{
		filePath(name),
	}

	var body bytes.Buffer
	err = json.NewEncoder(&body).Encode(&content)
	if nil != err {
		err = errors.New("", err, errno.EIO)
		return
	}

	dbr := dropboxRequest{
		uri:      self.rpcUri,
		path:     "/files/delete_v2",
		body:     requestBody(&body),
		apiError: &deleteV2ApiError{},
	}
	err = self.sendrecv(&dbr, func(rsp *http.Response) error {
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *dropbox) Rename(oldname string, newname string) (err error) {
	var content = struct {
		FromPath string `json:"from_path"`
		ToPath   string `json:"to_path"`
	}{
		filePath(oldname),
		filePath(newname),
	}

	var body bytes.Buffer
	err = json.NewEncoder(&body).Encode(&content)
	if nil != err {
		err = errors.New("", err, errno.EIO)
		return
	}

	dbr := dropboxRequest{
		uri:      self.rpcUri,
		path:     "/files/move_v2",
		body:     requestBody(&body),
		apiError: &moveV2ApiError{},
	}
	err = self.sendrecv(&dbr, func(rsp *http.Response) error {
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *dropbox) OpenRead(
	name string, sig string) (
	info objio.ObjectInfo, reader io.ReadCloser, err error) {

	var content = struct {
		Path string `json:"path"`
	}{
		filePath(name),
	}

	arg, err := json.Marshal(&content)
	if nil != err {
		err = errors.New("", err, errno.EIO)
		return
	}

	header := http.Header{}
	header.Add("Dropbox-API-Arg", string(arg))
	if "" != sig {
		header.Add("If-None-Match", sig)
	}

	dbr := dropboxRequest{
		uri:         self.contentUri,
		path:        "/files/download",
		header:      header,
		noBodyClose: true,
		apiError:    &downloadApiError{},
	}
	err = self.sendrecv(&dbr, func(rsp *http.Response) error {
		if 200 != rsp.StatusCode {
			defer rsp.Body.Close()

			if 304 == rsp.StatusCode {
				return nil
			}

			return errors.New("bad HTTP status", nil, errno.EIO)
		}

		var content dropboxObjectInfo
		err := json.Unmarshal([]byte(rsp.Header.Get("Dropbox-API-Result")), &content)
		if nil != err {
			return err
		}

		content.Tag = "file"
		info = &content
		reader = rsp.Body
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *dropbox) OpenWrite(name string, size int64) (writer objio.WriteWaiter, err error) {
	writer = &dropboxWriter{owner: self, name: name, size: size}
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
