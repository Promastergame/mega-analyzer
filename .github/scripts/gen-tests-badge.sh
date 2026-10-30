#!/usr/bin/env bash
# Render a flat "tests: NNN" SVG badge with zero external services.
# Usage: gen-tests-badge.sh <test_count> <output.svg>
set -euo pipefail

count="${1:?usage: gen-tests-badge.sh <test_count> <output.svg>}"
out="${2:?usage: gen-tests-badge.sh <test_count> <output.svg>}"

# Color based on test count (green is always good)
color="#4c1"  # brightgreen

msg="${count}"
labelW=50
# Generous width for the value box
valW=$(( ${#msg} * 9 + 8 ))
total=$(( labelW + valW ))

# Scaled (×10) text geometry, the standard shields flat layout
lx=$(( labelW * 5 + 5 ))
ltl=$(( (labelW - 10) * 10 ))
vx=$(( labelW * 10 + valW * 5 - 10 ))
vtl=$(( (valW - 10) * 10 ))

cat > "$out" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${total}" height="20" role="img" aria-label="tests: ${msg}">
  <title>tests: ${msg}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelW}" height="20" fill="#555"/>
    <rect x="${labelW}" width="${valW}" height="20" fill="${color}"/>
    <rect width="${total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="${lx}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${ltl}">tests</text>
    <text x="${lx}" y="140" transform="scale(.1)" fill="#fff" textLength="${ltl}">tests</text>
    <text aria-hidden="true" x="${vx}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${vtl}">${msg}</text>
    <text x="${vx}" y="140" transform="scale(.1)" fill="#fff" textLength="${vtl}">${msg}</text>
  </g>
</svg>
SVG

echo "wrote $out (tests ${msg}, color ${color})"
