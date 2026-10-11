package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/closedloop"
	"github.com/Autumn-27/artex/db"
)

// The main Handler authenticates all these routes. No deployment/attack route.
func (s *Server) registerClosedLoop(mux *http.ServeMux) {
	s.registerClosedLoopLive(mux)
	s.registerClosedLoopRange(mux)
	mux.HandleFunc("POST /api/closed-loop/suggest", s.suggestClosedLoop)
	mux.HandleFunc("POST /api/closed-loop/evaluate", s.evaluateClosedLoop)
	mux.HandleFunc("POST /api/closed-loop/iterations", s.saveClosedLoopIteration)
	mux.HandleFunc("GET /api/closed-loop/iterations", s.listClosedLoopIterations)
	mux.HandleFunc("GET /api/closed-loop/iterations/{id}", s.getClosedLoopIteration)
	mux.HandleFunc("GET /api/closed-loop/iterations/{id}/export", s.exportClosedLoopIteration)
}
func writeClosedLoopError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, closedloop.ErrInvalid):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, db.ErrClosedLoopNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	default:
		log.Printf("[closed-loop] operation failed: %v", err)
		writeErr(w, http.StatusInternalServerError, "Closed-loop 평가를 처리하지 못했습니다")
	}
}
func (s *Server) suggestClosedLoop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var in struct {
		TuningLogs   string          `json:"tuning_logs"`
		BaselineRule closedloop.Rule `json:"baseline_rule"`
	}
	if !decodePurpleRequestLimit(w, r, &in, 14<<20) {
		return
	}
	result, err := closedloop.Suggest(in.TuningLogs, in.BaselineRule)
	if err != nil {
		writeClosedLoopError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (s *Server) evaluateClosedLoop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var in closedloop.Input
	if !decodePurpleRequestLimit(w, r, &in, 14<<20) {
		return
	}
	result, err := closedloop.Evaluate(in)
	if err != nil {
		writeClosedLoopError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (s *Server) saveClosedLoopIteration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var in closedloop.Input
	if !decodePurpleRequestLimit(w, r, &in, 14<<20) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	result, err := pg.SaveClosedLoopIteration(r.Context(), in)
	if err != nil {
		writeClosedLoopError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}
func (s *Server) listClosedLoopIterations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	limit := 20
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			writeErr(w, http.StatusBadRequest, "표시 개수는 1~100이어야 합니다")
			return
		}
		limit = parsed
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	records, err := pg.ListClosedLoopIterations(r.Context(), limit)
	if err != nil {
		writeClosedLoopError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"iterations": records})
}
func (s *Server) closedLoopRecord(w http.ResponseWriter, r *http.Request, export bool) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "올바른 반복 기록 ID를 입력하세요")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	record, err := pg.GetClosedLoopIteration(r.Context(), id, export)
	if err != nil {
		writeClosedLoopError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if export {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="closed-loop-%d.json"`, id))
	}
	writeJSON(w, http.StatusOK, record)
}
func (s *Server) getClosedLoopIteration(w http.ResponseWriter, r *http.Request) {
	s.closedLoopRecord(w, r, false)
}
func (s *Server) exportClosedLoopIteration(w http.ResponseWriter, r *http.Request) {
	s.closedLoopRecord(w, r, true)
}
