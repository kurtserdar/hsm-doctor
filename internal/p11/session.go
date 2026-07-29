package p11

import (
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

// Session wraps an open PKCS#11 session, optionally authenticated.
type Session struct {
	client *Client
	ctx    *pkcs11.Ctx
	handle pkcs11.SessionHandle
	slotID uint
	// loginRef is true when this session holds a reference on the token's
	// shared login state (see Client.logins).
	loginRef bool
}

// OpenSession opens a session on the given slot. When pin is non-empty a
// CKU_USER login is performed. Set rw to true only for operations that create
// objects (functional tests use ephemeral session objects).
//
// Login state is shared by all sessions of the application, so concurrent
// authenticated sessions are reference-counted: the token is logged out only
// when the last authenticated session closes.
func (c *Client) OpenSession(slotID uint, pin string, rw bool) (*Session, error) {
	flags := uint(pkcs11.CKF_SERIAL_SESSION)
	if rw {
		flags |= pkcs11.CKF_RW_SESSION
	}
	h, err := c.ctx.OpenSession(slotID, flags)
	if err != nil {
		return nil, wrap(fmt.Sprintf("C_OpenSession(slot %d)", slotID), err)
	}
	s := &Session{client: c, ctx: c.ctx, handle: h, slotID: slotID}
	if pin != "" {
		// The login itself is serialized so a concurrent pair cannot both
		// see "not logged in yet" and race the reference count.
		c.mu.Lock()
		err := c.ctx.Login(h, pkcs11.CKU_USER, pin)
		if err != nil {
			var pe pkcs11.Error
			// Being already logged in on another session is not a failure.
			if !errors.As(err, &pe) || pe != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
				c.mu.Unlock()
				_ = c.ctx.CloseSession(h)
				return nil, wrap("C_Login", err)
			}
		}
		// Both outcomes mean this session relies on the shared login.
		c.logins[slotID]++
		s.loginRef = true
		c.mu.Unlock()
	}
	return s, nil
}

// Close releases this session's login reference (logging the token out when
// it was the last authenticated session) and closes the session.
func (s *Session) Close() {
	if s.loginRef && s.client != nil {
		s.client.mu.Lock()
		s.client.logins[s.slotID]--
		if s.client.logins[s.slotID] <= 0 {
			delete(s.client.logins, s.slotID)
			_ = s.ctx.Logout(s.handle)
		}
		s.client.mu.Unlock()
	}
	_ = s.ctx.CloseSession(s.handle)
}

// Raw exposes the underlying context and handle for internal packages that
// need direct PKCS#11 calls (e.g. functional tests).
func (s *Session) Raw() (*pkcs11.Ctx, pkcs11.SessionHandle) {
	return s.ctx, s.handle
}

// FindObjects returns all object handles matching the given template.
func (s *Session) FindObjects(template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := s.ctx.FindObjectsInit(s.handle, template); err != nil {
		return nil, wrap("C_FindObjectsInit", err)
	}
	defer func() { _ = s.ctx.FindObjectsFinal(s.handle) }()

	var all []pkcs11.ObjectHandle
	for {
		batch, _, err := s.ctx.FindObjects(s.handle, 128)
		if err != nil {
			return nil, wrap("C_FindObjects", err)
		}
		if len(batch) == 0 {
			return all, nil
		}
		all = append(all, batch...)
	}
}

// AttrBytes fetches a single attribute value. The second return value is
// false when the token does not expose the attribute for this object, which
// is normal and must not be treated as an error. Attributes are fetched one
// at a time because some tokens fail a whole C_GetAttributeValue batch when
// any single attribute in it is unsupported.
func (s *Session) AttrBytes(obj pkcs11.ObjectHandle, typ uint) ([]byte, bool) {
	attrs, err := s.ctx.GetAttributeValue(s.handle, obj, []*pkcs11.Attribute{pkcs11.NewAttribute(typ, nil)})
	if err != nil || len(attrs) == 0 {
		return nil, false
	}
	return attrs[0].Value, true
}

// AttrBool fetches a single boolean attribute value.
func (s *Session) AttrBool(obj pkcs11.ObjectHandle, typ uint) (bool, bool) {
	v, ok := s.AttrBytes(obj, typ)
	if !ok || len(v) == 0 {
		return false, false
	}
	return v[0] != 0, true
}

// AttrUint fetches a single CK_ULONG attribute value (native endianness).
func (s *Session) AttrUint(obj pkcs11.ObjectHandle, typ uint) (uint, bool) {
	v, ok := s.AttrBytes(obj, typ)
	if !ok || len(v) == 0 {
		return 0, false
	}
	var out uint
	// CK_ULONG is little-endian on all platforms we build for.
	for i := len(v) - 1; i >= 0; i-- {
		out = out<<8 | uint(v[i])
	}
	return out, true
}
