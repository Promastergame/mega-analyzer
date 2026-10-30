package vulnscan

import "errors"

// Freeze marks the configuration immutable. Call it after validation and
// before handing the config to the scan engine; checks that receive a copy of
// a frozen config can assert Frozen() to detect accidental late mutation.
func (c *ScannerConfig) Freeze() { c.frozen = true }

// Frozen reports whether the configuration has been frozen.
func (c ScannerConfig) Frozen() bool { return c.frozen }

// Validate performs bounds checking on the configuration. A Fatal ScanError
// should be raised by callers if this returns non-nil.
func (c ScannerConfig) Validate() error {
	if c.MaxRPS <= 0 {
		return errors.New("vulnscan: MaxRPS must be positive")
	}
	if c.MaxWorkers <= 0 {
		return errors.New("vulnscan: MaxWorkers must be positive")
	}
	if c.MaxBodyBytes < 0 {
		return errors.New("vulnscan: MaxBodyBytes must be non-negative")
	}
	if c.ConfidenceThreshold < 0 || c.ConfidenceThreshold > 1 {
		return errors.New("vulnscan: ConfidenceThreshold must be within 0..1")
	}
	if c.Timeout < 0 {
		return errors.New("vulnscan: Timeout must be non-negative")
	}
	return nil
}
