package apkloader

// Keep the semantic decoder synchronized with the public Dalvik decoder.
// This initializer follows both legacy table initializers.
func init() {
	for op:=0xfa;op<=0xff;op++ {
		info:=opcodeTable[op]
		flags:=FlagThrow|FlagInvoke
		ref:=RefMethod
		if op==0xfc||op==0xfd {ref=RefCallSite}
		if op==0xfe {ref=RefMethodHandle;flags=FlagConst|FlagThrow}
		if op==0xff {ref=RefProto;flags=FlagConst|FlagThrow}
		opcodeMetaTable[op]=OpcodeMetadata{Name:info.Name,Format:info.Format,Size:info.Size,Flags:flags,RefKind:ref}
	}
}
