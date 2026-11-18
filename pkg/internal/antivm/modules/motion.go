package modules

import (
	"fmt"
	"math"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
)

func validateMotionProfile(p profile.SensorProfile) error {
	if p.MotionIntervalMillis != 0 && (p.MotionIntervalMillis < 100 || p.MotionIntervalMillis > 5000) {
		return fmt.Errorf("sensors: motion_interval_millis must be between 100 and 5000")
	}
	if p.MotionDurationSeconds != 0 && (p.MotionDurationSeconds < 5 || p.MotionDurationSeconds > 900) {
		return fmt.Errorf("sensors: motion_duration_seconds must be between 5 and 900")
	}
	return nil
}

func motionConfig(p profile.SensorProfile) *adapter.MotionConfig {
	if !p.Enabled || (!p.Accelerometer && !p.Gyroscope) {
		return nil
	}
	interval, duration := p.MotionIntervalMillis, p.MotionDurationSeconds
	if interval == 0 {
		interval = 250
	}
	if duration == 0 {
		duration = 900
	}
	const count = 32
	phase := float64(p.MotionSeed%1024) * 2 * math.Pi / 1024
	omega := 2 * math.Pi / (float64(count*interval) / 1000)
	cfg := &adapter.MotionConfig{IntervalMillis: interval, DurationSeconds: duration}
	for i := 0; i < count; i++ {
		t := phase + float64(i)*2*math.Pi/count
		x, y := 0.025*math.Sin(t), 0.018*math.Cos(t)
		frame := adapter.MotionFrame{}
		if p.Accelerometer {
			frame.Readings = append(frame.Readings, adapter.SensorVector{Name: "acceleration", Values: [3]float64{9.80665 * math.Sin(y), -9.80665 * math.Sin(x), 9.80665 * math.Cos(x) * math.Cos(y)}})
		}
		if p.Gyroscope {
			frame.Readings = append(frame.Readings, adapter.SensorVector{Name: "gyroscope", Values: [3]float64{0.025 * omega * math.Cos(t), -0.018 * omega * math.Sin(t), 0.004 * math.Sin(t)}})
		}
		cfg.Frames = append(cfg.Frames, frame)
	}
	return cfg
}
