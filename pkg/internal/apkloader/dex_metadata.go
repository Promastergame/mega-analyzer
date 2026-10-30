package apkloader

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// DEXValue retains the encoded kind, including float bit patterns and
// references. It is shared by annotations, static values and call sites.
type DEXValue struct {
	Kind byte
	Bits uint64
	Text string
	Elements []DEXValue
	Annotation *DEXAnnotation
}

type DEXAnnotation struct {
	Visibility byte
	Type string
	Elements []DEXAnnotationElement
}

type DEXAnnotationElement struct { Name string; Value DEXValue }
type DEXMethodHandle struct { Kind uint16; Target uint16 }
type DEXDebugEvent struct {
	PC uint32
	Line int32
	Op byte
	Register uint32
	Name, Type, Signature string
}
type DEXDebugInfo struct { FirstLine uint32; Parameters []string; Events []DEXDebugEvent }

type dexMetadataReader struct { p *DEXParser; off uint32; remaining int }

func (r *dexMetadataReader) uleb() (uint32, error) {
	v, n := r.p.readULEB128At(r.off)
	if n == 0 { return 0, errBadULEB128 }
	r.off += uint32(n)
	return v, nil
}

func (r *dexMetadataReader) annotation(depth int) (*DEXAnnotation, error) {
	if depth > 64 { return nil, fmt.Errorf("annotation nesting exceeds 64") }
	idx, err := r.uleb()
	if err != nil { return nil, err }
	if int(idx) >= len(r.p.types) { return nil, fmt.Errorf("annotation type index %d out of bounds", idx) }
	n, err := r.uleb()
	if err != nil || uint64(n) > uint64(r.remaining) { return nil, fmt.Errorf("invalid annotation element count") }
	a := &DEXAnnotation{Type:r.p.types[idx]}
	for i:=uint32(0); i<n; i++ {
		name, err := r.uleb()
		if err != nil || int(name)>=len(r.p.strings) { return nil, fmt.Errorf("invalid annotation name") }
		v, err := r.value(depth+1)
		if err != nil { return nil, err }
		a.Elements=append(a.Elements, DEXAnnotationElement{r.p.strings[name],v})
	}
	return a,nil
}

func (r *dexMetadataReader) array(depth int) ([]DEXValue,error) {
	n,err:=r.uleb()
	if err!=nil || uint64(n)>uint64(r.remaining) { return nil,fmt.Errorf("invalid encoded array size") }
	values:=make([]DEXValue,0,n)
	for i:=uint32(0);i<n;i++ { v,err:=r.value(depth+1);if err!=nil{return nil,err};values=append(values,v) }
	return values,nil
}

func (r *dexMetadataReader) value(depth int) (DEXValue,error) {
	if depth>64 || r.remaining<=0 || !r.p.boundsOK(r.off,1) {return DEXValue{},fmt.Errorf("truncated or over-nested encoded value")}
	r.remaining--
	h:=r.p.data[r.off];r.off++
	k, arg:=h&31,h>>5
	v:=DEXValue{Kind:k}
	if k==0x1c {if arg!=0{return v,fmt.Errorf("invalid array value_arg")};var err error;v.Elements,err=r.array(depth);return v,err}
	if k==0x1d {if arg!=0{return v,fmt.Errorf("invalid annotation value_arg")};var err error;v.Annotation,err=r.annotation(depth);return v,err}
	if k==0x1e {if arg!=0{return v,fmt.Errorf("invalid null value_arg")};return v,nil}
	if k==0x1f {if arg>1{return v,fmt.Errorf("invalid boolean value_arg")};v.Bits=uint64(arg);return v,nil}
	maxWidth:=0
	switch k {case 0:maxWidth=1;case 2,3:maxWidth=2;case 4,0x10,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b:maxWidth=4;case 6,0x11:maxWidth=8}
	n:=int(arg)+1
	if maxWidth==0||n>maxWidth||!r.p.boundsOK(r.off,uint32(n)){return v,fmt.Errorf("invalid encoded value 0x%x width %d",k,n)}
	for i:=0;i<n;i++ {v.Bits|=uint64(r.p.data[r.off+uint32(i)])<<uint(8*i)}
	r.off+=uint32(n)
	switch k {
	case 0,2,4,6: shift:=uint(64-8*n);v.Bits=uint64(int64(v.Bits<<shift)>>shift)
	case 0x10,0x11:v.Bits<<=uint(8*(maxWidth-n))
	case 0x15:if v.Bits>=uint64(len(r.p.protos)){return v,fmt.Errorf("invalid proto index")};v.Text=r.p.protoDescriptor(uint32(v.Bits))
	case 0x16:if v.Bits>=uint64(len(r.p.methodHandles)){return v,fmt.Errorf("invalid method handle index")};v.Text=r.p.methodHandleText(uint32(v.Bits))
	case 0x17:if v.Bits>=uint64(len(r.p.strings)){return v,fmt.Errorf("invalid string index")};v.Text=r.p.strings[v.Bits]
	case 0x18:if v.Bits>=uint64(len(r.p.types)){return v,fmt.Errorf("invalid type index")};v.Text=r.p.types[v.Bits]
	case 0x19,0x1b:if v.Bits>=uint64(len(r.p.fields)){return v,fmt.Errorf("invalid field index")};v.Text=resolveField(uint32(v.Bits),r.p)
	case 0x1a:if v.Bits>=uint64(len(r.p.methods)){return v,fmt.Errorf("invalid method index")};v.Text=resolveMethod(uint32(v.Bits),r.p)
	}
	return v,nil
}

func (p *DEXParser) readDEXValues(off uint32) ([]DEXValue,error) {
	r:=dexMetadataReader{p:p,off:off,remaining:len(p.data)}
	return r.array(0)
}

func (p *DEXParser) protoDescriptor(idx uint32) string {
	if p==nil||int(idx)>=len(p.protos){return fmt.Sprintf("proto@%04x",idx)}
	v:=p.protos[idx];return "("+strings.Join(v.Parameters,"")+")"+v.ReturnType
}

var dexHandleNames=[]string{"static-put","static-get","instance-put","instance-get","invoke-static","invoke-instance","invoke-constructor","invoke-direct","invoke-interface"}
func (p *DEXParser) methodHandleText(idx uint32) string {
	if p==nil||int(idx)>=len(p.methodHandles){return fmt.Sprintf("handle@%04x",idx)}
	h:=p.methodHandles[idx]
	if int(h.Kind)>=len(dexHandleNames){return fmt.Sprintf("handle@%04x",idx)}
	ref:=resolveMethod(uint32(h.Target),p);if h.Kind<4{ref=resolveField(uint32(h.Target),p)}
	return dexHandleNames[h.Kind]+"@"+ref
}

func (p *DEXParser) callSiteText(idx uint32) string {
	if p==nil||int(idx)>=len(p.callSites){return fmt.Sprintf("callsite@%04x",idx)}
	v:=p.callSites[idx]
	if len(v)<3{return fmt.Sprintf("callsite@%04x",idx)}
	args:=make([]string,0,len(v)-1)
	for _,a:=range v[1:]{args=append(args,formatDEXValue(a,""))}
	return fmt.Sprintf("call_site_%d(%s)@%s",idx,strings.Join(args,", "),strings.TrimPrefix(v[0].Text,"invoke-static@"))
}

func (p *DEXParser) parseExtendedTables() error {
	if len(p.data)<56{return nil}
	mapOff:=leU32(p.data,52)
	if mapOff==0{return nil}
	if !p.boundsOK(mapOff,4){return fmt.Errorf("invalid map_list offset")}
	n:=leU32(p.data,mapOff)
	if uint64(mapOff)+4+uint64(n)*12>uint64(len(p.data)){return fmt.Errorf("truncated map_list")}
	var sitesOff,sitesCount uint32
	for i:=uint32(0);i<n;i++{
		off:=mapOff+4+i*12;k:=leU16(p.data,off);count,pos:=leU32(p.data,off+4),leU32(p.data,off+8)
		switch k {
		case 7:sitesOff,sitesCount=pos,count
		case 8:
			if uint64(pos)+uint64(count)*8>uint64(len(p.data)){return fmt.Errorf("truncated method_handles")}
			p.methodHandles=make([]DEXMethodHandle,count)
			for j:=range p.methodHandles{
				base:=pos+uint32(j)*8;h:=DEXMethodHandle{leU16(p.data,base),leU16(p.data,base+4)}
				if h.Kind>8||(h.Kind<4&&int(h.Target)>=len(p.fields))||(h.Kind>=4&&int(h.Target)>=len(p.methods)){return fmt.Errorf("invalid method handle %d",j)}
				p.methodHandles[j]=h
			}
		}
	}
	if uint64(sitesOff)+uint64(sitesCount)*4>uint64(len(p.data)){return fmt.Errorf("truncated call_site_ids")}
	for i:=uint32(0);i<sitesCount;i++{
		v,err:=p.readDEXValues(leU32(p.data,sitesOff+4*i))
		if err!=nil{return err}
		if len(v)<3||v[0].Kind!=0x16||v[1].Kind!=0x17||v[2].Kind!=0x15{return fmt.Errorf("invalid call site %d",i)}
		p.callSites=append(p.callSites,v)
	}
	return nil
}

func (p *DEXParser) readAnnotationSet(off uint32) ([]DEXAnnotation,error) {
	if off==0{return nil,nil}
	if !p.boundsOK(off,4){return nil,fmt.Errorf("invalid annotation set")}
	n:=leU32(p.data,off)
	if uint64(off)+4+uint64(n)*4>uint64(len(p.data)){return nil,fmt.Errorf("truncated annotation set")}
	var out []DEXAnnotation
	for i:=uint32(0);i<n;i++{
		pos:=leU32(p.data,off+4+i*4)
		if !p.boundsOK(pos,1)||p.data[pos]>2{return nil,fmt.Errorf("invalid annotation item")}
		r:=dexMetadataReader{p:p,off:pos+1,remaining:len(p.data)}
		a,err:=r.annotation(0);if err!=nil{return nil,err};a.Visibility=p.data[pos];out=append(out,*a)
	}
	return out,nil
}

func (p *DEXParser) parseClassMetadata(c *ClassDef) error {
	if c.StaticValuesOff!=0 {
		v,err:=p.readDEXValues(c.StaticValuesOff);if err!=nil{return err}
		if len(v)>len(c.StaticFields){return fmt.Errorf("too many static values for %s",c.ClassName)}
		for i:=range v{c.StaticFields[i].InitialValue=&v[i]}
	}
	off:=c.AnnotationsOff
	if off==0{return nil}
	if !p.boundsOK(off,16){return fmt.Errorf("truncated annotations directory")}
	var err error
	c.Annotations,err=p.readAnnotationSet(leU32(p.data,off));if err!=nil{return err}
	nf,nm,np:=leU32(p.data,off+4),leU32(p.data,off+8),leU32(p.data,off+12)
	if uint64(off)+16+(uint64(nf)+uint64(nm)+uint64(np))*8>uint64(len(p.data)){return fmt.Errorf("truncated annotations directory entries")}
	fields:=map[uint32]*EncodedField{};for _,f:=range append(append([]*EncodedField{},c.StaticFields...),c.InstanceFields...){fields[f.FieldIdx]=f}
	methods:=map[uint32]*EncodedMethod{};for _,m:=range append(append([]*EncodedMethod{},c.DirectMethods...),c.VirtualMethods...){methods[m.MethodIdx]=m}
	pos:=off+16
	for i:=uint32(0);i<nf;i++{idx,at:=leU32(p.data,pos),leU32(p.data,pos+4);pos+=8;f:=fields[idx];if f==nil{return fmt.Errorf("annotation references undeclared field")};f.Annotations,err=p.readAnnotationSet(at);if err!=nil{return err}}
	for i:=uint32(0);i<nm;i++{idx,at:=leU32(p.data,pos),leU32(p.data,pos+4);pos+=8;m:=methods[idx];if m==nil{return fmt.Errorf("annotation references undeclared method")};m.Annotations,err=p.readAnnotationSet(at);if err!=nil{return err}}
	for i:=uint32(0);i<np;i++{
		idx,at:=leU32(p.data,pos),leU32(p.data,pos+4);pos+=8;m:=methods[idx]
		if m==nil||!p.boundsOK(at,4){return fmt.Errorf("invalid parameter annotations")}
		n:=leU32(p.data,at)
		if uint64(at)+4+uint64(n)*4>uint64(len(p.data))||int(n)>len(m.Parameters){return fmt.Errorf("invalid parameter annotation count")}
		m.ParameterAnnotations=make([][]DEXAnnotation,n)
		for j:=uint32(0);j<n;j++{m.ParameterAnnotations[j],err=p.readAnnotationSet(leU32(p.data,at+4+4*j));if err!=nil{return err}}
	}
	return nil
}

func formatDEXValue(v DEXValue, indent string) string {
	switch v.Kind {
	case 0:return strconv.FormatInt(int64(v.Bits),10)+"t"
	case 2:return strconv.FormatInt(int64(v.Bits),10)+"s"
	case 3:return strconv.QuoteRuneToASCII(rune(v.Bits))
	case 4:return strconv.FormatInt(int64(v.Bits),10)
	case 6:return strconv.FormatInt(int64(v.Bits),10)+"L"
	case 0x10:return strconv.FormatFloat(float64(math.Float32frombits(uint32(v.Bits))),'g',-1,32)+"f"
	case 0x11:return strconv.FormatFloat(math.Float64frombits(v.Bits),'g',-1,64)+"d"
	case 0x17:return quoteSmaliString(v.Text)
	case 0x15,0x16,0x18,0x19,0x1a:return v.Text
	case 0x1b:return ".enum "+v.Text
	case 0x1c:
		parts:=make([]string,len(v.Elements));for i,x:=range v.Elements{parts[i]=formatDEXValue(x,indent+"    ")}
		return "{\n"+indent+"    "+strings.Join(parts,",\n"+indent+"    ")+"\n"+indent+"}"
	case 0x1d:
		if v.Annotation==nil{return "null"}
		var b strings.Builder;b.WriteString(".subannotation "+v.Annotation.Type+"\n")
		for _,e:=range v.Annotation.Elements{b.WriteString(indent+"    "+e.Name+" = "+formatDEXValue(e.Value,indent+"    ")+"\n")}
		b.WriteString(indent+".end subannotation");return b.String()
	case 0x1e:return "null"
	case 0x1f:if v.Bits!=0{return "true"};return "false"
	}
	return "null"
}

func formatDEXAnnotations(annotations []DEXAnnotation, indent string) string {
	var b strings.Builder
	for _,a:=range annotations{
		vis:="runtime";if a.Visibility==0{vis="build"};if a.Visibility==2{vis="system"}
		b.WriteString(indent+".annotation "+vis+" "+a.Type+"\n")
		for _,e:=range a.Elements{b.WriteString(indent+"    "+e.Name+" = "+formatDEXValue(e.Value,indent+"    ")+"\n")}
		b.WriteString(indent+".end annotation\n")
	}
	return b.String()
}
