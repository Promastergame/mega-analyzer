package adapter

const (
	// ThermalTemperaturePath is the kernel interface used by native probes.
	ThermalTemperaturePath = "/sys/class/thermal/thermal_zone0/temp"
	// ThermalTemperatureKey stores the raw reading in millidegrees Celsius.
	ThermalTemperatureKey = "thermal_zone0.temperature"
)
