package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sessionproxy/internal/domain"
	"sessionproxy/internal/service"
	appmw "sessionproxy/internal/transport/http/middleware"
)

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name,omitempty"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !decodeJSON(r, &req) || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	user, err := s.Auth.Register(r.Context(), req.Email, req.Password, req.DisplayName)
	if err != nil {
		if errors.Is(err, service.ErrEmailTaken) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		s.Logger.Error("register failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": user.ID, "email": user.Email})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(r, &req) {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	token, user, err := s.Auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "user_id": user.ID})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	userID := appmw.UserID(r.Context())
	user, err := s.Users.GetByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": user.ID, "email": user.Email, "display_name": user.DisplayName})
}

type createDeviceRequest struct {
	Name        string `json:"name,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func (s *Server) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	var req createDeviceRequest
	if !decodeJSON(r, &req) {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	d := domain.Device{UserID: appmw.UserID(r.Context())}
	if req.Name != "" {
		d.Name = &req.Name
	}
	if req.Fingerprint != "" {
		d.Fingerprint = &req.Fingerprint
	}
	created, err := s.Devices.Create(r.Context(), d)
	if err != nil {
		s.Logger.Error("create device failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.Devices.ListByUser(r.Context(), appmw.UserID(r.Context()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "deviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	if err := s.Devices.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type createAPIKeyRequest struct {
	Label     string     `json:"label,omitempty"`
	DeviceID  *uuid.UUID `json:"device_id,omitempty"`
	ExpiresIn int64      `json:"expires_in_seconds,omitempty"`
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req createAPIKeyRequest
	if !decodeJSON(r, &req) {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * time.Second)
		expiresAt = &t
	}
	rawKey, key, err := s.Auth.CreateAPIKey(r.Context(), appmw.UserID(r.Context()), req.Label, req.DeviceID, expiresAt)
	if err != nil {
		s.Logger.Error("create api key failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// raw_key is only ever returned here - the value_hash column cannot be
	// reversed, matching how password_hash and value_encrypted are handled.
	writeJSON(w, http.StatusCreated, map[string]any{"id": key.ID, "raw_key": rawKey, "label": key.Label})
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.APIKeys.ListByUser(r.Context(), appmw.UserID(r.Context()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid api key id")
		return
	}
	if err := s.APIKeys.Revoke(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
