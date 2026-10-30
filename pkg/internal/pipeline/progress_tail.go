package pipeline

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/types"
)

type activeFileProgress struct {
	path       string
	fileType   types.FileType
	phase      string
	startedAt  time.Time
	unitsDone  int64
	unitsTotal int64
}

func (p *Pipeline) startActiveJob(job FileJob) {
	if p == nil {
		return
	}
	p.activeMu.Lock()
	if p.active == nil {
		p.active = make(map[string]activeFileProgress)
	}
	p.active[job.RelPath] = activeFileProgress{
		path: job.RelPath, fileType: job.Type, phase: "analyzing", startedAt: time.Now(),
	}
	p.activeMu.Unlock()
}

func (p *Pipeline) updateActiveJob(path, phase string, done, total int64) {
	if p == nil {
		return
	}
	p.activeMu.Lock()
	item, ok := p.active[path]
	if ok {
		item.phase = phase
		item.unitsDone = done
		item.unitsTotal = total
		p.active[path] = item
	}
	p.activeMu.Unlock()
}

func (p *Pipeline) finishActiveJob(path string) {
	if p == nil {
		return
	}
	p.activeMu.Lock()
	delete(p.active, path)
	p.activeMu.Unlock()
}

func (p *Pipeline) activeProgressStatus(now time.Time) string {
	p.activeMu.Lock()
	items := make([]activeFileProgress, 0, len(p.active))
	for _, item := range p.active {
		items = append(items, item)
	}
	p.activeMu.Unlock()
	if len(items) == 0 {
		return "finishing worker queue"
	}
	sort.Slice(items, func(i, j int) bool { return items[i].startedAt.Before(items[j].startedAt) })
	item := items[0]
	name := filepath.ToSlash(item.path)
	if len(name) > 58 {
		name = "…/" + strings.TrimLeft(name[len(name)-55:], "/")
	}
	phase := item.phase
	if phase == "" {
		phase = "analyzing"
	}
	if item.unitsTotal > 0 {
		phase += fmt.Sprintf(" %d/%d", item.unitsDone, item.unitsTotal)
	} else if item.unitsDone > 0 {
		phase += fmt.Sprintf(" %d", item.unitsDone)
	}
	age := now.Sub(item.startedAt).Round(time.Second)
	status := fmt.Sprintf("%s · %s · %s", phase, name, age)
	if len(items) > 1 {
		status += fmt.Sprintf(" · +%d active", len(items)-1)
	}
	return status
}
