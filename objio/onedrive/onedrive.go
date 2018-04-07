/*
 * onedrive.go
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

package onedrive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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

// OneDrive and OneDrive Business invalid characters.
// See https://docs.microsoft.com/en-us/onedrive/developer/rest-api/concepts/addressing-driveitems
//
// The invalid map is produced by the following Python script:
//     reserved = r'\*<>?:|"#%'
//     l = [str(int(0 < i < 32 or chr(i) in reserved)) for i in xrange(0, 128)]
//     print "0x%08x" % int("".join(l[0:32]), 2)
//     print "0x%08x" % int("".join(l[32:64]), 2)
//     print "0x%08x" % int("".join(l[64:96]), 2)
//     print "0x%08x" % int("".join(l[96:128]), 2)
var invalidNameChars = [4]uint32{
	0x7fffffff,
	0x3420002b,
	0x00000008,
	0x00000008,
}

func encodeName(name string) string {
	b := strings.Builder{}
	for i := 0; len(name) > i; i++ {
		c := name[i]
		if (len(name)-1 == i && '.' == c) ||
			(128 > c && 0 != (invalidNameChars[c>>5]&(0x80000000>>(c&0x1f)))) {
			b.WriteRune(rune(c) | 0xf000)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func decodeName(name string) string {
	b := strings.Builder{}
	for _, r := range name {
		if 0xf000 <= r && r <= 0xf0ff {
			r &^= 0xf000
		}
		b.WriteRune(r)
	}
	return b.String()
}

type codedName string

func (v codedName) MarshalJSON() ([]byte, error) {
	s := encodeName(string(v))
	return json.Marshal(s)
}

func (v *codedName) UnmarshalJSON(b []byte) error {
	if nil == v {
		return errors.New(": nil pointer")
	}
	var s string
	err := json.Unmarshal(b, &s)
	if nil != err {
		return err
	}
	*v = codedName(decodeName(s))
	return nil
}

type presence bool

func (v *presence) UnmarshalJSON([]byte) error {
	if nil == v {
		return errors.New(": nil pointer")
	}
	*v = true
	return nil
}

const (
	stgInfoQuery = "select=quota"
	objInfoQuery = "select=" +
		"name,size,createdDateTime,lastModifiedDateTime,root,folder,file,cTag,deleted"
	removeQuery   = "select=folder,file,cTag"
	renameQuery   = "select=id,parentReference,file,cTag"
	renameIdQuery = "select=id"
	readQuery     = objInfoQuery + ",@microsoft.graph.downloadUrl"
)

type onedriveStorageInfo struct {
	FTotalSize int64 `json:"total"`
	FFreeSize  int64 `json:"remaining"`
}

func (self *onedriveStorageInfo) IsCaseInsensitive() bool {
	return true
}

func (self *onedriveStorageInfo) IsReadOnly() bool {
	return false
}

func (self *onedriveStorageInfo) MaxComponentLength() int {
	return 255 // !!!: just a guess!
}

func (self *onedriveStorageInfo) TotalSize() int64 {
	return self.FTotalSize
}

func (self *onedriveStorageInfo) FreeSize() int64 {
	return self.FFreeSize
}

type onedriveObjectInfo struct {
	FName    codedName `json:"name"`
	FSize    int64     `json:"size"`
	FBtime   time.Time `json:"createdDateTime"`
	FMtime   time.Time `json:"lastModifiedDateTime"`
	FRoot    presence  `json:"root"`
	FFolder  presence  `json:"folder"`
	FFile    presence  `json:"file"`
	FSig     string    `json:"cTag"`
	FDeleted presence  `json:"deleted"`
}

func (info *onedriveObjectInfo) Name() string {
	if bool(info.FRoot) {
		return "/"
	}
	return string(info.FName)
}

func (info *onedriveObjectInfo) Size() int64 {
	return info.FSize
}

func (info *onedriveObjectInfo) Btime() time.Time {
	return info.FBtime
}

func (info *onedriveObjectInfo) Mtime() time.Time {
	return info.FMtime
}

func (info *onedriveObjectInfo) IsDir() bool {
	return bool(info.FFolder) && !bool(info.FFile)
}

func (info *onedriveObjectInfo) Sig() string {
	return info.FSig
}

type onedriveRequest struct {
	method          string
	uri             *url.URL
	header          http.Header
	body            io.ReadCloser
	noAuthorization bool
	noRedirect      bool
	noBodyClose     bool
}

type onedriveReader struct {
	owner *onedrive
	uri   *url.URL
	body  io.ReadCloser
	mux   sync.Mutex
}

func (self *onedriveReader) Read(p []byte) (n int, err error) {
	self.mux.Lock()
	defer self.mux.Unlock()

	if nil == self.body {
		odr := onedriveRequest{
			method:          "GET",
			uri:             self.uri,
			noAuthorization: true,
			noBodyClose:     true,
		}
		err = self.owner.sendrecv(&odr, func(rsp *http.Response) error {
			self.body = rsp.Body
			return nil
		})
		if nil != err {
			err = errors.New("", err, errno.EIO)
			return
		}
	}

	n, err = self.body.Read(p)
	return
}

func (self *onedriveReader) ReadAt(p []byte, off int64) (n int, err error) {
	header := http.Header{}
	header.Add("Range", fmt.Sprintf("bytes=%d-%d", off, off+int64(len(p))-1))
	odr := onedriveRequest{
		method:          "GET",
		uri:             self.uri,
		header:          header,
		noAuthorization: true,
	}
	err = self.owner.sendrecv(&odr, func(rsp *http.Response) (err error) {
		if 206 == rsp.StatusCode {
			n, err = io.ReadAtLeast(rsp.Body, p, len(p))
			if io.ErrUnexpectedEOF == err {
				err = nil
			}
		} else if 416 == rsp.StatusCode {
			err = io.EOF
		} else {
			err = errors.New("bad HTTP status", nil, errno.EIO)
		}
		return
	})
	if nil != err && io.EOF != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *onedriveReader) Close() (err error) {
	self.mux.Lock()
	defer self.mux.Unlock()

	if nil != self.body {
		err = self.body.Close()
	}

	return
}

const fragmentSize = 4 * 320 * 1024 // onedrive's base upload fragment size is 320KiB

type onedriveWriter struct {
	owner     *onedrive
	name      string
	size      int64
	off       int64
	uploadUri *url.URL
	body      bytes.Buffer
	info      objio.ObjectInfo
	mux       sync.Mutex
}

func (self *onedriveWriter) uploadSmall() (err error) {
	endoff := self.off + int64(self.body.Len())

	header := http.Header{}
	header.Add("Content-type", "application/octet-stream")
	odr := onedriveRequest{
		method: "PUT",
		uri:    self.owner.requestUri("/content", "", self.name),
		header: header,
		body:   ioutil.NopCloser(&self.body),
	}
	err = self.owner.sendrecv(&odr, func(rsp *http.Response) error {
		if 200 > rsp.StatusCode || rsp.StatusCode > 201 {
			return errors.New("bad HTTP status", nil, errno.EIO)
		}

		var content onedriveObjectInfo
		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}

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

func (self *onedriveWriter) uploadLarge() (err error) {
	if nil == self.uploadUri {
		var content = struct {
			Item struct {
				Conflict string `json:"@microsoft.graph.conflictBehavior"`
			} `json:"item"`
		}{
			Item: struct {
				Conflict string `json:"@microsoft.graph.conflictBehavior"`
			}{
				Conflict: "replace",
			},
		}

		var body bytes.Buffer
		err = json.NewEncoder(&body).Encode(&content)
		if nil != err {
			return
		}

		odr := onedriveRequest{
			method: "POST",
			uri:    self.owner.requestUri("/createUploadSession", "", self.name),
			body:   ioutil.NopCloser(&body),
		}
		err = self.owner.sendrecv(&odr, func(rsp *http.Response) error {
			var content struct {
				UploadUrl string `json:"uploadUrl"`
			}

			err := json.NewDecoder(rsp.Body).Decode(&content)
			if nil != err {
				return err
			}
			uri, err := url.Parse(content.UploadUrl)
			if nil != err {
				return errors.New("bad upload URL", nil, errno.EIO)
			}

			self.uploadUri = uri
			return nil
		})
		if nil != err {
			err = errors.New("", err, errno.EIO)
			return
		}
	}

	endoff := self.off + int64(self.body.Len())
	header := http.Header{}
	header.Add("Content-type", "application/octet-stream")
	header.Add("Content-Range", fmt.Sprintf("bytes %d-%d/%d", self.off, endoff-1, self.size))
	odr := onedriveRequest{
		method:          "PUT",
		uri:             self.uploadUri,
		header:          header,
		body:            ioutil.NopCloser(&self.body),
		noAuthorization: false,
	}
	err = self.owner.sendrecv(&odr, func(rsp *http.Response) error {
		if 202 == rsp.StatusCode {
			return nil
		}
		if 200 > rsp.StatusCode || rsp.StatusCode > 201 {
			return errors.New("bad HTTP status", nil, errno.EIO)
		}

		var content onedriveObjectInfo
		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}

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

func (self *onedriveWriter) Write(p []byte) (written int, err error) {
	self.mux.Lock()
	defer self.mux.Unlock()

	for 0 != len(p) {
		n := fragmentSize - self.body.Len()
		if n > len(p) {
			n = len(p)
		}

		self.body.Write(p[:n]) // bytes.(*Buffer).Write cannot fail
		p = p[n:]

		if fragmentSize == self.body.Len() && (0 != len(p) || nil != self.uploadUri) {
			err = self.uploadLarge()
			if nil != err {
				return
			}
		}

		written += n
	}

	return
}

func (self *onedriveWriter) Close() (err error) {
	self.mux.Lock()
	defer self.mux.Unlock()

	self.uploadUri = nil
	self.off = 0
	self.body.Reset()
	return nil
}

func (self *onedriveWriter) Wait() (info objio.ObjectInfo, err error) {
	self.mux.Lock()
	defer self.mux.Unlock()

	if nil != self.uploadUri {
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

type onedrive struct {
	graphUri   *url.URL
	session    auth.Session
	httpClient *http.Client
}

func (self *onedrive) requestUri(stream, query, name string) *url.URL {
	uri := *self.graphUri

	name = strings.TrimPrefix(name, "/")
	name = encodeName(name)
	if "" == name {
		uri.Path = path.Join(uri.Path, "root", stream)
	} else if "" == stream {
		uri.Path = path.Join(uri.Path, "root:", name)
	} else {
		uri.Path = path.Join(uri.Path, "root:", name+":", stream)
	}
	uri.RawQuery = query

	return &uri
}

var errnomap = map[string]errno.Errno{
	"accessDenied":         errno.EACCES,
	"activityLimitReached": errno.ENOSPC, //errno.EDQUOT,
	"generalException":     errno.EIO,
	"invalidRange":         errno.EINVAL,
	"invalidRequest":       errno.EIO,
	"itemNotFound":         errno.ENOENT,
	"malwareDetected":      errno.EIO,
	"nameAlreadyExists":    errno.EEXIST,
	"notAllowed":           errno.EPERM,
	"notSupported":         errno.ENOSYS,
	"resourceModified":     errno.EIO,
	"resyncRequired":       errno.EIO,
	"quotaLimitReached":    errno.ENOSPC, //errno.EDQUOT,
	"unauthenticated":      errno.EACCES,
}

func (self *onedrive) sendrecv(odr *onedriveRequest, fn func(*http.Response) error) error {
	header := http.Header{}
	if nil != odr.header {
		for k, v := range odr.header {
			header[k] = v
		}
	}

	if nil != odr.body && "" == header.Get("Content-type") {
		header.Add("Content-type", "application/json")
	}

	if !odr.noAuthorization && nil != self.session {
		if refr, ok := self.session.(auth.SessionRefresher); ok {
			err := refr.Refresh(false)
			if nil != err {
				return err
			}
		}

		creds := self.session.Credentials()
		header.Add("Authorization", creds.Get("token_type")+" "+creds.Get("access_token"))
	}

	req := &http.Request{
		Method:     odr.method,
		URL:        odr.uri,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
		Host:       odr.uri.Host,
		Body:       odr.body,
	}

	if odr.noRedirect {
		httputil.AllowRedirect(req, false)
		defer httputil.AllowRedirect(req, true)
	}

	rsp, err := self.httpClient.Do(req)
	if nil != err {
		return err
	}

	if 412 == rsp.StatusCode && "" != odr.header.Get("If-Match") {
		// special case If-Match requests!
	} else if 416 == rsp.StatusCode && "" != odr.header.Get("Range") {
		// special case Range requests!
	} else if 400 <= rsp.StatusCode {
		defer rsp.Body.Close()

		var content struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}

		errmesg := ""
		errcode := errno.EIO
		err = json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			errmesg = fmt.Sprintf("HTTP %d", rsp.StatusCode)
		} else {
			errmesg = fmt.Sprintf("HTTP %d: %s: %s", rsp.StatusCode,
				content.Error.Code, content.Error.Message)
			if rc, ok := errnomap[content.Error.Code]; ok {
				errcode = rc
			}
		}
		return errors.New(errmesg, err, errcode)
	}

	if !odr.noBodyClose {
		defer rsp.Body.Close()
	}

	return fn(rsp)
}

func (self *onedrive) Info(getsize bool) (info objio.StorageInfo, err error) {
	if !getsize {
		info = &onedriveStorageInfo{}
		return
	}

	uri := *self.graphUri
	uri.RawQuery = stgInfoQuery
	odr := onedriveRequest{
		method: "GET",
		uri:    &uri,
	}
	err = self.sendrecv(&odr, func(rsp *http.Response) error {
		var content struct {
			Info *onedriveStorageInfo `json:"quota"`
		}
		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}
		info = content.Info
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *onedrive) List(
	prefix string, imarker string, maxcount int) (
	omarker string, infos []objio.ObjectInfo, err error) {

	var uri *url.URL
	if "" == imarker {
		if 0 < maxcount {
			uri = self.requestUri("/children",
				fmt.Sprintf("%s&top=%d", objInfoQuery, maxcount), prefix)
		} else {
			uri = self.requestUri("/children", objInfoQuery, prefix)
			maxcount = -1
		}
	} else {
		uri, err = url.Parse(imarker)
		if nil != err {
			err = errors.New(": invalid marker", err, errno.EINVAL)
			return
		}
		maxcount = -1
	}

	odr := onedriveRequest{
		method: "GET",
		uri:    uri,
	}
	err = self.sendrecv(&odr, func(rsp *http.Response) error {
		var content struct {
			Infos  []*onedriveObjectInfo `json:"value"`
			Marker string                `json:"@odata.nextLink"`
		}
		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}
		omarker = content.Marker
		infos = make([]objio.ObjectInfo, len(content.Infos))
		i := 0
		for _, v := range content.Infos {
			if maxcount == i {
				break
			}
			if v.FDeleted {
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

func (self *onedrive) Stat(name string) (info objio.ObjectInfo, err error) {
	odr := onedriveRequest{
		method: "GET",
		uri:    self.requestUri("", objInfoQuery, name),
	}
	err = self.sendrecv(&odr, func(rsp *http.Response) error {
		var content onedriveObjectInfo
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

func (self *onedrive) Mkdir(prefix string) (info objio.ObjectInfo, err error) {
	dir, name := path.Split(prefix)
	var content = struct {
		Name     codedName       `json:"name"`
		Folder   map[string]bool `json:"folder"`
		Conflict string          `json:"@microsoft.graph.conflictBehavior"`
	}{
		Name:     codedName(name),
		Folder:   map[string]bool{},
		Conflict: "fail",
	}

	var body bytes.Buffer
	err = json.NewEncoder(&body).Encode(&content)
	if nil != err {
		return
	}

	odr := onedriveRequest{
		method: "POST",
		uri:    self.requestUri("/children", "", dir),
		body:   ioutil.NopCloser(&body),
	}
	err = self.sendrecv(&odr, func(rsp *http.Response) error {
		var content onedriveObjectInfo
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

func (self *onedrive) Rmdir(prefix string) (err error) {
	return self.remove(prefix, true)
}

func (self *onedrive) Remove(name string) (err error) {
	return self.remove(name, false)
}

func (self *onedrive) remove(name string, dir bool) (err error) {
	var content struct {
		Folder struct {
			ChildCount int `json:"childCount"`
		} `json:"folder"`
		File presence `json:"file"`
		Sig  string   `json:"cTag"`
	}

	odr := onedriveRequest{
		method: "GET",
		uri:    self.requestUri("", removeQuery, name),
	}
	err = self.sendrecv(&odr, func(rsp *http.Response) error {
		return json.NewDecoder(rsp.Body).Decode(&content)
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
		return
	}

	var header http.Header
	if dir {
		if content.File {
			err = errors.New("", err, errno.ENOTDIR)
			return
		}
		if 0 < content.Folder.ChildCount {
			err = errors.New("", err, errno.ENOTEMPTY)
			return
		}

		// comment the following lines as OneDrive seems to fail with 500 otherwise
		// header = http.Header{}
		// header.Add("If-Match", content.Sig)
	} else {
		if !content.File || 0 < content.Folder.ChildCount {
			err = errors.New("", err, errno.EISDIR)
			return
		}
	}

	odr = onedriveRequest{
		method: "DELETE",
		uri:    self.requestUri("", "", name),
		header: header,
	}
	err = self.sendrecv(&odr, func(rsp *http.Response) error {
		if 412 == rsp.StatusCode {
			return errno.ENOTEMPTY
		}
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *onedrive) Rename(oldname string, newname string) (err error) {
	var content struct {
		ParentReference struct {
			Id string `json:"id"`
		}
		File presence `json:"file"`
		Sig  string   `json:"cTag"`
	}

	odr := onedriveRequest{
		method: "GET",
		uri:    self.requestUri("", renameQuery, newname),
	}
	err = self.sendrecv(&odr, func(rsp *http.Response) error {
		return json.NewDecoder(rsp.Body).Decode(&content)
	})

	if nil == err {
		// disallow renaming over existing directories! (NOTE: POSIX allows this!)
		if !bool(content.File) && !strings.EqualFold(oldname, newname) {
			err = errors.New("", err, errno.EISDIR)
			return
		}

		_, newname = path.Split(newname)
	} else if errors.HasAttachment(err, errno.ENOENT) {
		var dir string
		dir, newname = path.Split(newname)

		odr := onedriveRequest{
			method: "GET",
			uri:    self.requestUri("", renameIdQuery, dir),
		}
		err = self.sendrecv(&odr, func(rsp *http.Response) error {
			var idcontent struct {
				Id string `json:"id"`
			}

			err := json.NewDecoder(rsp.Body).Decode(&idcontent)
			if nil == err {
				content.ParentReference.Id = idcontent.Id
			}

			return err
		})
	}

	if nil != err {
		err = errors.New("", err, errno.EIO)
		return
	}

	var newcontent = struct {
		Name            codedName `json:"name"`
		ParentReference struct {
			Id string `json:"id"`
		} `json:"parentReference"`
		Conflict string `json:"@microsoft.graph.conflictBehavior"`
	}{
		Name: codedName(newname),
		ParentReference: struct {
			Id string `json:"id"`
		}{
			Id: content.ParentReference.Id,
		},
		Conflict: "replace",
	}

	var body bytes.Buffer
	err = json.NewEncoder(&body).Encode(&newcontent)
	if nil != err {
		return
	}

	odr = onedriveRequest{
		method: "PATCH",
		uri:    self.requestUri("", "", oldname),
		body:   ioutil.NopCloser(&body),
	}
	err = self.sendrecv(&odr, func(rsp *http.Response) error {
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *onedrive) OpenRead(
	name string, sig string) (
	info objio.ObjectInfo, reader io.ReadCloser, err error) {

	var header http.Header
	if "" != sig {
		header = http.Header{}
		header.Add("If-None-Match", sig)
	}

	odr := onedriveRequest{
		method: "GET",
		uri:    self.requestUri("", readQuery, name),
		header: header,
		//noRedirect: true,
	}
	err = self.sendrecv(&odr, func(rsp *http.Response) error {
		if 200 != rsp.StatusCode {
			if 304 == rsp.StatusCode {
				return nil
			}

			return errors.New("bad HTTP status", nil, errno.EIO)
		}

		var content struct {
			onedriveObjectInfo
			DownloadUrl string `json:"@microsoft.graph.downloadUrl"`
		}

		err := json.NewDecoder(rsp.Body).Decode(&content)
		if nil != err {
			return err
		}

		uri, err := url.Parse(content.DownloadUrl)
		if "" == content.DownloadUrl || nil != err {
			return errors.New("bad downloadUrl", nil, errno.EIO)
		}

		info = &content.onedriveObjectInfo
		reader = &onedriveReader{owner: self, uri: uri}
		return nil
	})
	if nil != err {
		err = errors.New("", err, errno.EIO)
	}

	return
}

func (self *onedrive) OpenWrite(name string, size int64) (writer objio.WriteWaiter, err error) {
	writer = &onedriveWriter{owner: self, name: name, size: size}
	return
}

// New creates an object that can access onedrive storage.
func New(args ...interface{}) (interface{}, error) {
	var (
		graphUri   *url.URL
		session    auth.Session
		creds      auth.CredentialMap
		httpClient = httputil.DefaultClient
	)

	for _, arg := range args {
		switch a := arg.(type) {
		case string:
			uri, err := url.Parse(a)
			if nil != err {
				return nil, errors.New(": invalid uri "+a, err, errno.EINVAL)
			}
			if nil == graphUri {
				graphUri = uri
			}
		case auth.Session:
			session = a
		case auth.CredentialMap:
			creds = a
		case *http.Client:
			httpClient = a
		}
	}

	if nil == graphUri {
		return nil, errors.New(": missing graphUri", nil, errno.EINVAL)
	}

	if nil == session {
		if nil == creds {
			creds = auth.CredentialMap{}
		}
		s, err := authSession(httpClient, creds)
		if nil != err {
			return nil, errors.New("", err, errno.EACCES)
		}
		session = s
	}

	self := &onedrive{
		graphUri:   graphUri,
		session:    session,
		httpClient: httpClient,
	}

	return self, nil
}

var _ objio.ObjectStorage = (*onedrive)(nil)

const DefaultUri = "https://graph.microsoft.com/v1.0/me/drive"

func authSession(httpClient *http.Client, creds auth.CredentialMap) (auth.Session, error) {
	a, err := auth.Registry.NewObject("oauth2", httpClient,
		"https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		"https://login.microsoftonline.com/common/oauth2/v2.0/token")
	if nil != err {
		return nil, err
	}

	return a.(auth.Auth).Session(creds)
}

func AuthSession(creds auth.CredentialMap) (auth.Session, error) {
	return authSession(httputil.DefaultClient, creds)
}

// Load is used to ensure that this package is linked.
func Load() {
	oauth2.Load()
}

func init() {
	objio.Registry.RegisterFactory("onedrive", New)
}
