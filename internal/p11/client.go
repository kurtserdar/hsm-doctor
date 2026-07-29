package p11

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
)

// Client wraps a loaded PKCS#11 module.
type Client struct {
	ctx  *pkcs11.Ctx
	path string
}

// Open loads and initializes the PKCS#11 module at the given path.
func Open(path string) (*Client, error) {
	ctx := pkcs11.New(path)
	if ctx == nil {
		return nil, fmt.Errorf("cannot load PKCS#11 module %q", path)
	}
	if err := ctx.Initialize(); err != nil {
		var pe pkcs11.Error
		// An already-initialized library is fine to reuse.
		if !errors.As(err, &pe) || pe != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			ctx.Destroy()
			return nil, wrap("C_Initialize", err)
		}
	}
	return &Client{ctx: ctx, path: path}, nil
}

// Close finalizes and unloads the module.
func (c *Client) Close() {
	if c.ctx != nil {
		_ = c.ctx.Finalize()
		c.ctx.Destroy()
		c.ctx = nil
	}
}

// Info returns information about the loaded module.
func (c *Client) Info() (ModuleInfo, error) {
	info, err := c.ctx.GetInfo()
	if err != nil {
		return ModuleInfo{}, wrap("C_GetInfo", err)
	}
	return ModuleInfo{
		Path:            c.path,
		CryptokiVersion: fmt.Sprintf("%d.%d", info.CryptokiVersion.Major, info.CryptokiVersion.Minor),
		Manufacturer:    clean(info.ManufacturerID),
		Description:     clean(info.LibraryDescription),
		LibraryVersion:  fmt.Sprintf("%d.%d", info.LibraryVersion.Major, info.LibraryVersion.Minor),
	}, nil
}

// Slots lists all slots reported by the module, including token details for
// slots that have a token present.
func (c *Client) Slots() ([]SlotInfo, error) {
	ids, err := c.ctx.GetSlotList(false)
	if err != nil {
		return nil, wrap("C_GetSlotList", err)
	}
	slots := make([]SlotInfo, 0, len(ids))
	for _, id := range ids {
		si, err := c.ctx.GetSlotInfo(id)
		if err != nil {
			return nil, wrap(fmt.Sprintf("C_GetSlotInfo(slot %d)", id), err)
		}
		slot := SlotInfo{
			ID:           id,
			Description:  clean(si.SlotDescription),
			Manufacturer: clean(si.ManufacturerID),
			TokenPresent: si.Flags&pkcs11.CKF_TOKEN_PRESENT != 0,
		}
		if slot.TokenPresent {
			ti, err := c.ctx.GetTokenInfo(id)
			if err != nil {
				return nil, wrap(fmt.Sprintf("C_GetTokenInfo(slot %d)", id), err)
			}
			slot.Token = &TokenInfo{
				Label:           clean(ti.Label),
				Manufacturer:    clean(ti.ManufacturerID),
				Model:           clean(ti.Model),
				SerialNumber:    clean(ti.SerialNumber),
				HardwareVersion: fmt.Sprintf("%d.%d", ti.HardwareVersion.Major, ti.HardwareVersion.Minor),
				FirmwareVersion: fmt.Sprintf("%d.%d", ti.FirmwareVersion.Major, ti.FirmwareVersion.Minor),
				Initialized:     ti.Flags&pkcs11.CKF_TOKEN_INITIALIZED != 0,
				LoginRequired:   ti.Flags&pkcs11.CKF_LOGIN_REQUIRED != 0,
			}
		}
		slots = append(slots, slot)
	}
	return slots, nil
}

// mechanismFlagNames maps CKF_* mechanism capability flags to short names.
var mechanismFlagNames = []struct {
	flag uint
	name string
}{
	{pkcs11.CKF_HW, "HW"},
	{pkcs11.CKF_ENCRYPT, "ENCRYPT"},
	{pkcs11.CKF_DECRYPT, "DECRYPT"},
	{pkcs11.CKF_DIGEST, "DIGEST"},
	{pkcs11.CKF_SIGN, "SIGN"},
	{pkcs11.CKF_SIGN_RECOVER, "SIGN_RECOVER"},
	{pkcs11.CKF_VERIFY, "VERIFY"},
	{pkcs11.CKF_VERIFY_RECOVER, "VERIFY_RECOVER"},
	{pkcs11.CKF_GENERATE, "GENERATE"},
	{pkcs11.CKF_GENERATE_KEY_PAIR, "GENERATE_KEY_PAIR"},
	{pkcs11.CKF_WRAP, "WRAP"},
	{pkcs11.CKF_UNWRAP, "UNWRAP"},
	{pkcs11.CKF_DERIVE, "DERIVE"},
}

// Mechanisms lists all mechanisms supported by the token in the given slot.
func (c *Client) Mechanisms(slotID uint) ([]Mechanism, error) {
	list, err := c.ctx.GetMechanismList(slotID)
	if err != nil {
		return nil, wrap(fmt.Sprintf("C_GetMechanismList(slot %d)", slotID), err)
	}
	mechs := make([]Mechanism, 0, len(list))
	for _, m := range list {
		mech := Mechanism{Code: m.Mechanism, Name: MechanismName(m.Mechanism)}
		if mi, err := c.ctx.GetMechanismInfo(slotID, []*pkcs11.Mechanism{m}); err == nil {
			mech.MinKeySize = mi.MinKeySize
			mech.MaxKeySize = mi.MaxKeySize
			mech.Hardware = mi.Flags&pkcs11.CKF_HW != 0
			for _, f := range mechanismFlagNames {
				if mi.Flags&f.flag != 0 && f.name != "HW" {
					mech.Flags = append(mech.Flags, f.name)
				}
			}
		}
		mechs = append(mechs, mech)
	}
	return mechs, nil
}

// clean trims trailing spaces and NUL padding from fixed-width PKCS#11 fields.
func clean(s string) string {
	return strings.TrimRight(s, " \x00")
}

// wrap annotates a PKCS#11 error with the failing call and the CKR_* name.
func wrap(call string, err error) error {
	var pe pkcs11.Error
	if errors.As(err, &pe) {
		return fmt.Errorf("%s failed: %s (0x%08X)", call, ReturnCodeName(uint(pe)), uint(pe))
	}
	return fmt.Errorf("%s failed: %w", call, err)
}
