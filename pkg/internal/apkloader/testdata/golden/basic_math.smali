# ═══════════════════════════════════════════════════════════════════════════════
# PRETTY SMALI OUTPUT — Deobfuscation Pipeline
# ═══════════════════════════════════════════════════════════════════════════════
#
# This output contains recovered names and annotations from the deobfuscation pipeline.
#
# Confidence Scores:
#   - 80-100: High confidence (reliable recovered names)
#   - 50-79:  Medium confidence (reasonable but may need verification)
#   - 0-49:   Low confidence (original names preserved)
#
# Legend:
#   [RECOVERED] — Name recovered from analysis
#   [ORIGINAL]  — Original obfuscated name
#   [CONFIDENCE] — Confidence score (0-100)
#   [OBFUSCATION] — Detected obfuscation technique
#
# ═══════════════════════════════════════════════════════════════════════════════

# VARIABLE RECOVERY
# ─────────────────────────────────────────────────────────────────────────────
# v0: [ORIGINAL: v0] [RECOVERED: value] [CONFIDENCE: 50%] (Selected from 1 candidates (source: usage_pattern))
# v1: [ORIGINAL: v1] [RECOVERED: value] [CONFIDENCE: 50%] (Selected from 1 candidates (source: usage_pattern))

# CONSTANT PROPAGATION
# ─────────────────────────────────────────────────────────────────────────────
# v0 = 10
# v1 = 20

# CONTROL FLOW GRAPH STRUCTURE
# ─────────────────────────────────────────────────────────────────────────────
# Total Basic Blocks: 1
# Reachable Blocks: 1
# Unreachable Blocks: 0
# Loop Headers: 0
# Exception Handlers: 0

.method public basic_math()V
    # Block 0
    const v0, 0xa # v0 → value (50%)
    const v1, 0x14 # v1 → value (50%)
    add v2, v0, v1
    return v2 # v0 → value (50%)

.end method
