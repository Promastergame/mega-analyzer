package modules

import (
	"math"
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/antivm/profile"
)

func TestMotionProfileIsReproducibleAndChangesBothSensors(t *testing.T) {
	p := profile.SensorProfile{Enabled: true, Accelerometer: true, Gyroscope: true, MotionSeed: 42}
	cfg := motionConfig(p)
	if !reflect.DeepEqual(cfg, motionConfig(p)) {
		t.Fatal("same seed changed the trace")
	}
	p.MotionSeed++
	if reflect.DeepEqual(cfg, motionConfig(p)) {
		t.Fatal("different seed did not change the trace")
	}
	for _, frame := range cfg.Frames {
		a := frame.Readings[0].Values
		g := math.Sqrt(a[0]*a[0] + a[1]*a[1] + a[2]*a[2])
		if g < 9.7 || g > 9.9 {
			t.Fatalf("acceleration magnitude=%f", g)
		}
	}
	for sensor := 0; sensor < 2; sensor++ {
		if cfg.Frames[0].Readings[sensor].Values == cfg.Frames[8].Readings[sensor].Values {
			t.Fatal("static sensor trace")
		}
	}
	p.Gyroscope = false
	if len(motionConfig(p).Frames[0].Readings) != 1 {
		t.Fatal("disabled gyroscope was scheduled")
	}
	p.Enabled = false
	if motionConfig(p) != nil {
		t.Fatal("disabled sensors scheduled playback")
	}
}
