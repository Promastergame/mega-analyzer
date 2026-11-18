package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"decisionai/gameagent"
	"decisionai/games"
	"decisionai/mcpclient"
	"decisionai/vision"
)

// runInteraction handles commands which do not require text-model weights.
func runInteraction(cmd, input, output, imagePath string, v vision.Describer) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 15*time.Minute)
	defer timeout()
	if cmd == "see" {
		if v == nil {
			return fmt.Errorf("image reader is not configured")
		}
		if imagePath == "" {
			return fmt.Errorf("see requires -image <PNG/JPEG/GIF file>")
		}
		f, err := os.Open(imagePath)
		if err != nil {
			return err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, vision.MaxImageBytes+1))
		if err != nil {
			return err
		}
		if len(b) > vision.MaxImageBytes {
			return fmt.Errorf("image exceeds 1 MiB")
		}
		im := vision.Image{Data: base64.StdEncoding.EncodeToString(b), MIMEType: http.DetectContentType(b)}
		analysis, err := (vision.Local{}).Analyze(ctx, im)
		if err != nil {
			return err
		}
		return emit(output, analysis)
	}
	b, err := read(input)
	if err != nil {
		return err
	}
	if cmd == "game" {
		var s gameRequest
		if err := strict(b, &s); err != nil {
			return err
		}
		d, err := solveGame(ctx, s)
		if err != nil {
			return err
		}
		return emit(output, d)
	}
	var config gameagent.Config
	if cmd == "mcp-tools" {
		if err := strict(b, &config.Server); err != nil {
			return err
		}
	} else if err := strict(b, &config); err != nil {
		return err
	}
	c, err := mcpclient.Start(ctx, config.Server)
	if err != nil {
		return err
	}
	defer c.Close()
	tools, err := c.ListTools(ctx)
	if err != nil {
		return err
	}
	if cmd == "mcp-tools" {
		return emit(output, tools)
	}
	report, runErr := gameagent.Run(ctx, c, v, config)
	if err := emit(output, struct {
		gameagent.Report
		Error string `json:"error,omitempty"`
	}{report, errorText(runErr)}); err != nil {
		return err
	}
	return runErr
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func gameHandler(w http.ResponseWriter, r *http.Request) {
	var s gameRequest
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err == nil {
		err = strict(b, &s)
	}
	var result games.Decision
	if err == nil {
		result, err = solveGame(r.Context(), s)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}

type gameRequest struct {
	games.State
	Image *vision.Image `json:"image,omitempty"`
}

func solveGame(ctx context.Context, r gameRequest) (games.Decision, error) {
	if r.Image != nil {
		if len(r.Board) > 0 || len(r.Grid) > 0 || r.Piece != "" || r.Next != "" || r.Active != nil || r.Revision != "" {
			return games.Decision{}, fmt.Errorf("image requests cannot include board, grid, piece, next, active or revision")
		}
		observed, err := (vision.Local{}).ReadGame(ctx, r.Game, []vision.Image{*r.Image})
		if err != nil {
			return games.Decision{}, err
		}
		if r.Player != "" {
			if r.Game == "russian_checkers" && observed.Player != r.Player {
				return games.Decision{}, fmt.Errorf("configured side does not match the visible turn")
			}
			if r.Game != "russian_checkers" {
				observed.Player = r.Player
			}
		}
		r.State = observed
	}
	if err := ctx.Err(); err != nil {
		return games.Decision{}, err
	}
	d, err := games.SolveContext(ctx, r.State)
	if err == nil && r.Image != nil {
		d.Source = "image"
		d.Observed = &r.State
	}
	return d, err
}
