/*
 * types.go
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
	"github.com/billziss-gh/golib/errors"
	"github.com/billziss-gh/objfs/errno"
)

// Based on the encoding described below, but limited only to the types we care about:
//
// https://github.com/dropbox/dropbox-sdk-go-unofficial/blob/ba23178/generator/README.md

type presence bool

func (v *presence) UnmarshalJSON([]byte) error {
	if nil == v {
		return errors.New(": nil pointer")
	}
	*v = true
	return nil
}

// API errors (HTTP 409)

type apiError interface {
	Message() string
	Errno() errno.Errno
}

type baseApiError struct {
	ErrorSummary string `json:"error_summary"`
}

func (e *baseApiError) Message() string {
	return e.ErrorSummary
}

type createFolderV2ApiError struct {
	baseApiError
	Error *createFolderError `json:"error"`
}

func (e *createFolderV2ApiError) Errno() errno.Errno {
	switch {
	case nil != e.Error:
		return e.Error.Errno()
	default:
		return errno.EIO
	}
}

type createFolderError struct {
	Tag  string      `json:".tag"`
	Path *writeError `json:"path"`
}

func (e *createFolderError) Errno() errno.Errno {
	switch {
	case nil != e.Path:
		return e.Path.Errno()
	default:
		return errno.EIO
	}
}

type deleteV2ApiError struct {
	baseApiError
	Error *deleteError `json:"error"`
}

func (e *deleteV2ApiError) Errno() errno.Errno {
	switch {
	case nil != e.Error:
		return e.Error.Errno()
	default:
		return errno.EIO
	}
}

type deleteError struct {
	Tag        string       `json:".tag"`
	PathLookup *lookupError `json:"path_lookup"`
	PathWrite  *writeError  `json:"path_write"`
}

func (e *deleteError) Errno() errno.Errno {
	switch {
	case nil != e.PathLookup:
		return e.PathLookup.Errno()
	case nil != e.PathWrite:
		return e.PathWrite.Errno()
	default:
		return errno.EIO
	}
}

type downloadApiError struct {
	baseApiError
	Error *downloadError `json:"error"`
}

func (e *downloadApiError) Errno() errno.Errno {
	switch {
	case nil != e.Error:
		return e.Error.Errno()
	default:
		return errno.EIO
	}
}

type downloadError struct {
	Tag  string       `json:".tag"`
	Path *lookupError `json:"path"`
}

func (e *downloadError) Errno() errno.Errno {
	switch {
	case nil != e.Path:
		return e.Path.Errno()
	default:
		return errno.EIO
	}
}

type getMetadataApiError struct {
	baseApiError
	Error *getMetadataError `json:"error"`
}

func (e *getMetadataApiError) Errno() errno.Errno {
	switch {
	case nil != e.Error:
		return e.Error.Errno()
	default:
		return errno.EIO
	}
}

type getMetadataError struct {
	Tag  string       `json:".tag"`
	Path *lookupError `json:"path"`
}

func (e *getMetadataError) Errno() errno.Errno {
	switch {
	case nil != e.Path:
		return e.Path.Errno()
	default:
		return errno.EIO
	}
}

type listFolderApiError struct {
	baseApiError
	Error *listFolderError `json:"error"`
}

func (e *listFolderApiError) Errno() errno.Errno {
	switch {
	case nil != e.Error:
		return e.Error.Errno()
	default:
		return errno.EIO
	}
}

type listFolderError struct {
	Tag  string       `json:".tag"`
	Path *lookupError `json:"path"`
}

func (e *listFolderError) Errno() errno.Errno {
	switch {
	case nil != e.Path:
		return e.Path.Errno()
	default:
		return errno.EIO
	}
}

type listFolderContinueApiError struct {
	baseApiError
	Error *listFolderContinueError `json:"error"`
}

func (e *listFolderContinueApiError) Errno() errno.Errno {
	switch {
	case nil != e.Error:
		return e.Error.Errno()
	default:
		return errno.EIO
	}
}

type listFolderContinueError struct {
	Tag  string       `json:".tag"`
	Path *lookupError `json:"path"`
}

func (e *listFolderContinueError) Errno() errno.Errno {
	switch {
	case nil != e.Path:
		return e.Path.Errno()
	case "reset" == e.Tag:
		return errno.EINVAL
	default:
		return errno.EIO
	}
}

type uploadApiError struct {
	baseApiError
	Error *uploadError `json:"error"`
}

func (e *uploadApiError) Errno() errno.Errno {
	switch {
	case nil != e.Error:
		return e.Error.Errno()
	default:
		return errno.EIO
	}
}

type uploadError struct {
	Tag             string             `json:".tag"`
	Path            *uploadWriteFailed `json:"path"`
	PropertiesError presence           `json:"properties_error"`
}

func (e *uploadError) Errno() errno.Errno {
	switch {
	case nil != e.Path:
		return e.Path.Errno()
	default:
		return errno.EIO
	}
}

type uploadWriteFailed struct {
	Reason          *writeError `json:"reason"`
	UploadSessionId string      `json:"upload_session_id"`
}

func (e *uploadWriteFailed) Errno() errno.Errno {
	switch {
	case nil != e.Reason:
		return e.Reason.Errno()
	default:
		return errno.EIO
	}
}

type uploadSessionAppendApiError struct {
	baseApiError
	Error *uploadSessionLookupError `json:"error"`
}

func (e *uploadSessionAppendApiError) Errno() errno.Errno {
	switch {
	case nil != e.Error:
		return e.Error.Errno()
	default:
		return errno.EIO
	}
}

type uploadSessionLookupError struct {
	Tag             string                    `json:".tag"`
	IncorrectOffset *uploadSessionOffsetError `json:"incorrect_offset"`
}

func (e *uploadSessionLookupError) Errno() errno.Errno {
	return errno.EIO
}

type uploadSessionOffsetError struct {
	CorrectOffset uint64 `json:"correct_offset"`
}

type uploadSessionFinishApiError struct {
	baseApiError
	Error *uploadSessionFinishError `json:"error"`
}

func (e *uploadSessionFinishApiError) Errno() errno.Errno {
	switch {
	case nil != e.Error:
		return e.Error.Errno()
	default:
		return errno.EIO
	}
}

type uploadSessionFinishError struct {
	Tag          string                    `json:".tag"`
	LookupFailed *uploadSessionLookupError `json:"lookup_failed"`
	Path         *writeError               `json:"path"`
}

func (e *uploadSessionFinishError) Errno() errno.Errno {
	switch {
	case nil != e.LookupFailed:
		return e.LookupFailed.Errno()
	case nil != e.Path:
		return e.Path.Errno()
	default:
		return errno.EIO
	}
}

type lookupError struct {
	Tag           string   `json:".tag"`
	MalformedPath presence `json:"malformed_path"`
}

func (e *lookupError) Errno() (errc errno.Errno) {
	switch e.Tag {
	case "malformed_path":
		return errno.EPERM
	case "not_found":
		return errno.ENOENT
	case "not_file":
		return errno.EISDIR
	case "not_folder":
		return errno.ENOTDIR
	case "restricted_content":
		return errno.EACCES
	default:
		return errno.EIO
	}
}

type writeError struct {
	Tag           string   `json:".tag"`
	MalformedPath presence `json:"malformed_path"`
	Conflict      presence `json:"conflict"`
}

func (e *writeError) Errno() (errc errno.Errno) {
	switch e.Tag {
	case "malformed_path":
		return errno.EPERM
	case "conflict":
		return errno.EEXIST
	case "no_write_permission":
		return errno.EACCES
	case "insufficient_space":
		return errno.ENOSPC
	case "disallowed_name":
		return errno.EPERM
	case "team_folder":
		return errno.EPERM
	case "too_many_write_operations":
		return errno.ENOSPC //errno.EDQUOT
	default:
		return errno.EIO
	}
}

// API types

type spaceUsage struct {
	Used       uint64           `json:"used"`
	Allocation *spaceAllocation `json:"allocation"`
}

type spaceAllocation struct {
	Tag        string                     `json:".tag"`
	Allocated  uint64                     `json:"allocated"`
	Individual *individualSpaceAllocation `json:"individual"`
	Team       *teamSpaceAllocation       `json:"team"`
}

type individualSpaceAllocation struct {
	Allocated uint64 `json:"allocated"`
}

type teamSpaceAllocation struct {
	Used                         uint64                `json:"used"`
	Allocated                    uint64                `json:"allocated"`
	UserWithinTeamSpaceAllocated uint64                `json:"user_within_team_space_allocated"`
	UserWithinTeamSpaceLimitType *memberSpaceLimitType `json:"user_within_team_space_limit_type"`
}

type memberSpaceLimitType struct {
	Tag string `json:".tag"`
}

type listFolderResult struct {
	Entries []*dropboxObjectInfo `json:"entries"`
	Cursor  string               `json:"cursor"`
	HasMore bool                 `json:"has_more"`
}

type symlinkInfo struct {
	Target string `json:"target"`
}

type sharingInfo struct {
	ReadOnly     bool `json:"read_only"`     // files and folders
	TraverseOnly bool `json:"traverse_only"` // folders only
	NoAccess     bool `json:"no_access"`     // folders only
}

type createFolderResult struct {
	Metadata *dropboxObjectInfo `json:"metadata"`
}
