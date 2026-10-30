package ml

import (
 "fmt"
 "strconv"
 "strings"
)

// validationLines keeps physical line numbers but excludes comments and data.
// Payload entries are not executable labels; their target references are checked
// separately from this view.
func validationLines(code string) []string {
 lines := strings.Split(code, "\n")
 var state smaliNonCodeState
 for i, line := range lines {
  line = smaliCodeLine(line)
  if state.skip(line) { line = "" }
  lines[i] = line
 }
 return lines
}

// splitSmaliOperands respects quoted strings, register lists and call-site syntax.
func smaliRegisterOperands(line string) string {
 line = smaliCodeLine(line)
 fields := strings.Fields(line)
 if len(fields)<2 || strings.HasPrefix(fields[0],".") || strings.HasPrefix(fields[0],":") { return "" }
 operands, ok := splitSmaliOperands(strings.TrimSpace(strings.TrimPrefix(line,fields[0])))
 if !ok { return "" }
 var regs []string
 for _, operand := range operands {
  if strings.HasPrefix(operand,"{") { regs=append(regs,operand); continue }
  if len(operand)<2 || (operand[0]!='v' && operand[0]!='p') { continue }
  if _,err:=strconv.ParseUint(operand[1:],10,16); err==nil { regs=append(regs,operand) }
 }
 return strings.Join(regs," ")
}

func splitSmaliOperands(text string) ([]string, bool) {
 if strings.TrimSpace(text) == "" { return nil, true }
 var out []string
 start, depth := 0, 0
 quoted, escaped := false, false
 for i, c := range text {
  if quoted {
   if escaped { escaped = false } else if c == '\\' { escaped = true } else if c == '"' { quoted = false }
   continue
  }
  switch c {
  case '"': quoted = true
  case '{', '(': depth++
  case '}', ')': depth--; if depth < 0 { return nil, false }
  case ',':
   if depth == 0 { out = append(out, strings.TrimSpace(text[start:i])); start = i+1 }
  }
 }
 if quoted || depth != 0 { return nil, false }
 out = append(out, strings.TrimSpace(text[start:]))
 for _, s := range out { if s == "" { return nil, false } }
 return out, true
}

func smaliTypeEnd(s string, start int, allowVoid bool) (int, bool) {
 if start >= len(s) { return start, false }
 i := start
 for i < len(s) && s[i] == '[' { i++ }
 if i >= len(s) || i-start > 255 { return i, false }
 switch s[i] {
 case 'V': return i+1, allowVoid && i == start
 case 'Z','B','S','C','I','J','F','D': return i+1, true
 case 'L':
  end := strings.IndexByte(s[i:], ';')
  if end <= 1 { return i, false }
  name := s[i+1:i+end]
  if strings.ContainsAny(name, " .[();\t\r\n") { return i, false }
  return i+end+1, true
 }
 return i, false
}

func validSmaliType(s string, allowVoid bool) bool {
 end, ok := smaliTypeEnd(s, 0, allowVoid)
 return ok && end == len(s)
}

func validSmaliMethodDescriptor(s string) bool {
 if !strings.HasPrefix(s, "(") { return false }
 i := 1
 for i < len(s) && s[i] != ')' {
  next, ok := smaliTypeEnd(s, i, false)
  if !ok { return false }; i = next
 }
 return i < len(s) && validSmaliType(s[i+1:], true)
}

func validSmaliMember(s string, method bool) bool {
 parts := strings.SplitN(s, "->", 2)
 if len(parts) != 2 || !validSmaliType(parts[0], false) || !strings.HasPrefix(parts[0], "L") { return false }
 sep := ":"; if method { sep = "(" }
 i := strings.Index(parts[1], sep)
 if i <= 0 || strings.ContainsAny(parts[1][:i], " \t\r\n,;()") { return false }
 if method { return validSmaliMethodDescriptor(parts[1][i:]) }
 return validSmaliType(parts[1][i+1:], false)
}

func physicalSmaliRegister(s string, budget, params int) (int, bool) {
 if len(s) < 2 || (s[0] != 'v' && s[0] != 'p') { return 0, false }
 for _, c := range s[1:] { if c < '0' || c > '9' { return 0, false } }
 n, err := strconv.Atoi(s[1:]); if err != nil { return 0, false }
 if s[0] == 'p' {
  if n >= params { return 0, false }
  n += budget-params
 }
 return n, n >= 0 && n < budget
}

// Register limits come from the actual DEX format, not suffixes such as /16
// (literal width) or /jumbo (reference width).
func formatRegisterLimits(format string) []int {
 switch format {
 case "11n": return []int{15}
 case "12x", "22c", "22s", "22t": return []int{15,15}
 case "11x", "21s", "21h", "21c", "21t", "31i", "31c", "31t", "51l": return []int{255}
 case "22x": return []int{255,65535}
 case "32x": return []int{65535,65535}
 case "23x": return []int{255,255,255}
 case "22b": return []int{255,255}
 }
 return nil
}

func wideSmaliOperand(op string, index int) bool {
 switch {
 case strings.HasPrefix(op,"move-wide"): return index < 2
 case strings.Contains(op,"-wide"): return index == 0
 case strings.Contains(op,"-to-"):
  parts := strings.Split(op,"-to-")
  if index == 0 { return parts[1] == "long" || parts[1] == "double" }
  return parts[0] == "long" || parts[0] == "double"
 case strings.HasPrefix(op,"cmp"):
  return index > 0 && (strings.HasSuffix(op,"long") || strings.HasSuffix(op,"double"))
 case strings.Contains(op,"long"), strings.Contains(op,"double"):
  if strings.HasPrefix(op,"shl-") || strings.HasPrefix(op,"shr-") || strings.HasPrefix(op,"ushr-") {
   if strings.HasSuffix(op,"/2addr") { return index == 0 }; return index < 2
  }
  return true
 }
 return false
}

func (sv *SmaliValidator) validateOperandLines(lines []string, result *ValidationResult, strict bool) {
 budget := sv.extractRegisterCount(lines)
 params, _ := sv.methodParamRegisters(lines)
 add := func(i int, message string) {
  result.Valid = false
  result.Errors = append(result.Errors, ValidationError{Line:i+1, Code:ErrInvalidInstruction, Message:message, Context:lines[i]})
 }
 for i, line := range lines {
  if line == "" || strings.HasPrefix(line,".") || strings.HasPrefix(line,":") { continue }
  fields := strings.Fields(line)
  op, known := sv.opcodeTable[fields[0]]
  if !known { if strict { add(i,"Unknown opcode: "+fields[0]) }; continue }
  operands, ok := splitSmaliOperands(strings.TrimSpace(strings.TrimPrefix(line,op.Name)))
  if !ok { add(i,"Malformed operands"); continue }
  if op.Format == "35c" || op.Format == "3rc" || op.Format == "45cc" || op.Format == "4rcc" {
   if err := validateSmaliInvoke(op, operands, budget, params); err != nil { add(i,err.Error()) }
   continue
  }
  limits := formatRegisterLimits(op.Format)
  extra := 0
  switch op.Format {
  case "11n","21s","21h","21c","21t","31i","31c","31t","51l","22c","22s","22t","22b","10t","20t","30t": extra=1
  }
  if len(operands) != len(limits)+extra { add(i,"Wrong operand count for "+op.Name); continue }
  for j, limit := range limits {
   n, ok := physicalSmaliRegister(operands[j],budget,params)
   if !ok || n > limit || (wideSmaliOperand(op.Name,j) && n+1 >= budget) {
    result.Valid=false
    result.Errors=append(result.Errors,ValidationError{Line:i+1,Code:ErrRegisterOverflow,Message:fmt.Sprintf("Register %s exceeds budget %d, operand width or wide-pair budget for %s",operands[j],budget,op.Name),Context:line})
   }
  }
  if extra == 0 { continue }
  value := operands[len(operands)-1]
  valid := true
  switch op.Format {
  case "10t","20t","30t","21t","22t","31t":
   valid = spLabelRe.MatchString(value)
   if !valid { _, valid = parseSmaliLiteral(value) } // internal numeric-offset representation
  case "21c","31c","22c":
   switch {
   case strings.HasPrefix(op.Name,"const-string"):
    valid = len(value)>=2 && value[0]=='"' && value[len(value)-1]=='"'
   case op.Name=="const-method-type": valid=validSmaliMethodDescriptor(value)
   case op.Name=="const-method-handle":
    // Handle syntax differs by handle kind; reject rather than certify an
    // unparsed reference in strict mode.
    valid = !strict
   case strings.HasPrefix(op.Name,"iget"),strings.HasPrefix(op.Name,"iput"),strings.HasPrefix(op.Name,"sget"),strings.HasPrefix(op.Name,"sput"):
    valid=validSmaliMember(value,false)
   default: valid=validSmaliType(value,false)
   }
  default:
   n, parsed := parseSmaliLiteral(value)
   valid=parsed
   if parsed {
    switch op.Format {
    case "11n": valid=n>=-8 && n<=7
    case "21s","22s": valid=n>=-32768 && n<=32767
    case "22b": valid=n>=-128 && n<=127
    case "31i": valid=n>=-2147483648 && n<=4294967295
    case "21h":
     if strings.HasPrefix(op.Name,"const-wide") { valid=n&0xffffffffffff==0 } else { valid=n&0xffff==0 && n>=-2147483648 && n<=4294967295 }
    }
   }
  }
  if !valid { add(i,"Invalid operand "+value+" for "+op.Name) }
 }
}

func validateSmaliInvoke(op OpcodeInfo, operands []string, budget, params int) error {
 count := 2
 if op.Format=="45cc" || op.Format=="4rcc" { count=3 }
 if len(operands)!=count { return fmt.Errorf("wrong operand count for %s",op.Name) }
 list:=operands[0]
 if !strings.HasPrefix(list,"{") || !strings.HasSuffix(list,"}") { return fmt.Errorf("missing register list") }
 list=strings.TrimSpace(list[1:len(list)-1])
 var regs []int
 if op.Format=="3rc" || op.Format=="4rcc" {
  if list!="" {
   ends:=strings.Split(list,"..")
   if len(ends)!=2 { return fmt.Errorf("invalid register range") }
   a,okA:=physicalSmaliRegister(strings.TrimSpace(ends[0]),budget,params)
   b,okB:=physicalSmaliRegister(strings.TrimSpace(ends[1]),budget,params)
   if !okA || !okB || b<a || b-a+1>255 { return fmt.Errorf("register range out of bounds") }
   for n:=a;n<=b;n++ { regs=append(regs,n) }
  }
 } else if list!="" {
  for _, token:=range strings.Split(list,",") {
   n,ok:=physicalSmaliRegister(strings.TrimSpace(token),budget,params)
   if !ok || n>15 { return fmt.Errorf("invoke register does not fit four-bit field") }
   regs=append(regs,n)
  }
  if len(regs)>5 { return fmt.Errorf("invoke needs /range for more than five register words") }
 }
 if strings.HasPrefix(op.Name,"filled-new-array") {
  if !strings.HasPrefix(operands[1],"[") || !validSmaliType(operands[1],false) || operands[1]=="[J" || operands[1]=="[D" { return fmt.Errorf("invalid filled-new-array element type") }
  return nil
 }
 if strings.HasPrefix(op.Name,"invoke-custom") { return fmt.Errorf("invoke-custom call-site verification is unsupported; manual review required") }
 if !validSmaliMember(operands[1],true) { return fmt.Errorf("invalid method reference") }
 desc:=operands[1][strings.IndexByte(operands[1],'('):]
 static:=strings.HasPrefix(op.Name,"invoke-static")
 if count==3 {
  desc=operands[2]
  if !validSmaliMethodDescriptor(desc) { return fmt.Errorf("invalid polymorphic descriptor") }
 }
 if len(regs)!=countParamRegisters(desc,static) { return fmt.Errorf("invoke register count does not match descriptor") }
 word:=0; if !static { word=1 }
 for i:=1; i<len(desc) && desc[i]!=')'; {
  end, _:=smaliTypeEnd(desc,i,false)
  if desc[i]=='J' || desc[i]=='D' {
   if word+1>=len(regs) || regs[word+1]!=regs[word]+1 { return fmt.Errorf("non-adjacent wide argument registers") }; word++
  }
  word++; i=end
 }
 return nil
}
