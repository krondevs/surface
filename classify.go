package main

func ParseSurfaceHost(host string) (string, bool) {
	normalized := NormalizeHost(host)
	if !IsSurfaceName(normalized) {
		return "", false
	}
	return normalized, true
}
