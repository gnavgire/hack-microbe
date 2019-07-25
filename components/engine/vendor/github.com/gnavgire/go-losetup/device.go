package losetup

import (
	"fmt"
	"os"
	"bytes"
	"path/filepath"
)

// Device represents a loop device /dev/loop#
type Device struct {
	// device number (i.e. 7 if /dev/loop7)
	number uint64

	// flags with which to open the device with
	flags int
}

// open returns a file handle to /dev/loop# and returns an error if it cannot
// be opened.
func (device Device) open() (*os.File, error) {
	return os.OpenFile(device.Path(), device.flags, 0660)
}

// Path returns the path to the loopback device
func (device Device) Path() string {
	return fmt.Sprintf(DeviceFormatString, device.number)
}

// search device using backing file path
func GetDeviceFromBackingFilePath(backingFile string) (Device, error) {
	absPath, err := filepath.Abs(backingFile)
	if err != nil { return Device{}, err }

	// iterate through all the devices to match given backing file
	// (an alternatively way without having to hardcode an upper-bound (which could be right now too conservative?) might be to continue searching when GetInfo returns a device or error "device not backed by a file" but stop when any other error comes. But this hypothesis would have first to be validated)
	for i:=0; i < MaxLoopDevices; i++ {
		dev := Device{number:uint64(i), flags: os.O_RDWR}
		info, err := dev.GetInfo()
		if err == nil {
			filename := string(bytes.Trim(info.FileName[:], "\x00"))
			if filename == absPath { // found the device mounted for the given backing file
			    // set proper flags from info
				dev.flags = int(info.Flags)
				return dev, nil
			}
		}
	}

	return Device{}, fmt.Errorf("can not find a device for backing file %s", backingFile)
}

