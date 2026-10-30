package ml

import (
 "strings"
 "testing"
)

func TestStrictOperandValidation(t *testing.T) {
 tests:=[]struct{name, header, body string; valid bool}{
  {"unknown", "static f()V", ".locals 1\nunknown-opcode v0\nreturn-void",false},
  {"missing_literal", "static f()V", ".locals 1\nconst/4 v0\nreturn-void",false},
  {"extra_operand", "static f()V", ".locals 1\nreturn-void v0",false},
  {"bad_invoke_descriptor", "static f()V", ".locals 0\ninvoke-static {}, LA;->f(Q)V\nreturn-void",false},
  {"invoke_arg_count", "static f()V", ".locals 1\ninvoke-static {}, LA;->f(I)V\nreturn-void",false},
  {"invoke_narrow", "static f()V", ".locals 17\ninvoke-static {v16}, LA;->f(I)V\nreturn-void",false},
  {"invoke_range", "static f()V", ".locals 301\ninvoke-static/range {v300 .. v300}, LA;->f(I)V\nreturn-void",true},
  {"const16_register", "static f()V", ".locals 301\nconst/16 v300, 1\nreturn-void",false},
  {"jumbo_register", "static f()V", ".locals 301\nconst-string/jumbo v300, \"text\"\nreturn-void",false},
  {"move_from16_source", "static f()V", ".locals 301\nmove/from16 v0, v300\nreturn-void",true},
  {"move_from16_dest", "static f()V", ".locals 301\nmove/from16 v300, v0\nreturn-void",false},
  {"move16", "static f()V", ".locals 302\nmove/16 v301, v300\nreturn-void",true},
  {"p_alias_16", "f()V", ".locals 16\nconst/4 p0, 0\nreturn-void",false},
  {"p_alias_15", "f()V", ".locals 15\nconst/4 p0, 0\nreturn-void",true},
  {"p_wide_overflow", "static f(I)J", ".locals 0\nreturn-wide p0",false},
  {"wide_object_operand", "static f(LA;)J", ".locals 2\niget-wide v0, p0, LA;->x:J\nreturn-wide v0",true},
  {"wide_arg_pair", "static f()V", ".locals 3\ninvoke-static {v0, v2}, LA;->f(J)V\nreturn-void",false},
  {"filled_array", "static f()[I", ".locals 1\nconst/4 v0, 1\nfilled-new-array {v0}, [I\nmove-result-object v0\nreturn-object v0",true},
  {"strings_and_comments", "static f()V", ".locals 1\n# v999 p999 .registers 999\nconst-string v0, \"v999 # p999\"\nreturn-void",true},
  {"comment_literal_width", "static f()V", ".locals 1\nconst/4 v0, 100 # note\nreturn-void",false},
  {"annotation", "static f()V", ".locals 0\n.annotation runtime LA;\nvalue = \"v999\"\n.end annotation\nreturn-void",true},
 }
 for _,tt:=range tests {t.Run(tt.name,func(t *testing.T){
  code:=".method public "+tt.header+"\n"+tt.body+"\n.end method"
  result:=NewSmaliValidator().ValidateStrict(code)
  if result.Valid!=tt.valid {t.Fatalf("valid=%v want=%v: %+v\n%s",result.Valid,tt.valid,result.Errors,code)}
 })}
}

func TestStrictRegisterBoundaries(t *testing.T) {
 for _,tt:=range []struct{line string; valid bool}{
  {"const/4 v15, 7",true},{"const/4 v16, 7",false},
  {"const/16 v255, 32767",true},{"const/16 v256, 32767",false},
  {"const-wide v255, 1",true},{"const-wide v256, 1",false},
  {"add-int v255, v254, v253",true},{"add-int v256, v254, v253",false},
 } {
  t.Run(strings.ReplaceAll(tt.line," ","_"),func(t *testing.T){
   result:=NewSmaliValidator().ValidateStrict(".method static f()V\n.locals 300\n"+tt.line+"\nreturn-void\n.end method")
   if result.Valid!=tt.valid {t.Fatalf("%+v",result)}
  })
 }
}
