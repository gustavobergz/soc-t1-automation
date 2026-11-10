package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	blockTTL = 45 * time.Second
	operator = "analista-demo"
)

var protectedIPs = []string{managerIP, victimIP, soarIP}

type workflow struct {
	incident alert
	phase    string
}

type decision struct {
	Run        string `json:"run"`
	Incident   string `json:"incident"`
	Source     string `json:"source_ip"`
	ApprovedBy string `json:"approved_by"`
}

type block struct {
	request decision
	expires time.Time
}

func permittedSource(source string) bool {
	return !slices.Contains(protectedIPs, source) && source == attackIP
}

func (a *appliance) contain(w http.ResponseWriter, r *http.Request) {
	var request decision
	if !decode(w, r, soarIP, &request) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if request.Run != a.activeRun || !runID.MatchString(request.Run) || request.Incident != "INC-"+request.Run ||
		!permittedSource(request.Source) || request.ApprovedBy != operator {
		http.Error(w, "decisao fora da politica", http.StatusForbidden)
		return
	}
	if a.blocked != nil {
		if a.blocked.request == request {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "ja existe bloqueio ativo", http.StatusConflict)
		return
	}
	entry := &block{request: request, expires: time.Now().Add(blockTTL)}
	a.blocked = entry
	a.emit("endpoint.block_applied", request.Run, "Vítima aplicou o bloqueio temporário no serviço de demonstração.", fields{
		"source_ip": request.Source, "incident": request.Incident, "approved_by": request.ApprovedBy,
		"expires_at": entry.expires.UTC(), "ttl_seconds": int(blockTTL.Seconds()), "scope": "serviço HTTP de demonstração",
		"action": "http_block", "approval_id": approvalID(request.Run), "target_ip": victimIP,
	})
	time.AfterFunc(blockTTL, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.blocked == entry {
			a.releaseBlock("expiration", "policy")
		}
	})
	w.WriteHeader(http.StatusNoContent)
}

func (a *appliance) releaseBlock(reason, actor string) {
	request := a.blocked.request
	a.blocked = nil
	a.emit("endpoint.block_released", request.Run, "A origem foi liberada no serviço de demonstração.", fields{
		"source_ip": request.Source, "incident": request.Incident, "reason": reason, "actor": actor,
		"action": "http_unblock", "approval_id": approvalID(request.Run), "target_ip": victimIP,
	})
}

func (a *appliance) rollback(w http.ResponseWriter, r *http.Request) {
	var request decision
	if !decode(w, r, soarIP, &request) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if request.Run != a.activeRun || (a.blocked != nil && a.blocked.request != request) {
		http.Error(w, "rollback fora do escopo", http.StatusConflict)
		return
	}
	if a.blocked != nil {
		a.releaseBlock("rollback", request.ApprovedBy)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *appliance) playbook(w http.ResponseWriter, r *http.Request) {
	var incident alert
	if !decode(w, r, managerIP, &incident) {
		return
	}
	if !runID.MatchString(incident.Run) || incident.Incident != "INC-"+incident.Run || incident.User != account ||
		incident.Host != endpoint || len(incident.Evidence) == 0 || len(incident.Evidence) > 30 ||
		(incident.Mode != "manual" && !incident.ChainComplete) ||
		(incident.Mode != "manual" && incident.Mode != "auto" && incident.Mode != "failure" && incident.Mode != "llm") {
		http.Error(w, "incidente incompleto", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.incidents[incident.Run] != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	job := &workflow{incident: incident, phase: "triage"}
	a.incidents[incident.Run] = job
	w.WriteHeader(http.StatusNoContent)
	if incident.Mode == "manual" {
		a.emit("soar.manual_started", incident.Run, "O analista pode concluir a triagem a partir dos eventos brutos.", nil)
		return
	}
	a.emit("soar.enriched", incident.Run, "Contexto de reputação sintético, com mapeamento ATT&CK para as evidências.", fields{
		"incident": incident.Incident, "source_ip": incident.Source, "provider": "fixture local (campos de referência AbuseIPDB)",
		"reputation": simulatedReputation, "mitre": allowedTechniques, "simulation": true,
		"abuseipdb": "simulated", "virustotal": "not_queried", "external_query": false,
		"mitre_excluded": fields{"T1068": "sudo -l consulta permissões; não há evidência de exploração"},
	})
	a.beginTriage(job)
}

func approvalID(run string) string { return "APR-" + run }

func (a *appliance) requestApproval(job *workflow) {
	incident := job.incident
	if !permittedSource(incident.Source) {
		job.phase = "denied"
		a.emit("soar.policy_denied", incident.Run, "A origem está protegida ou fora do escopo autorizado.", fields{
			"incident": incident.Incident, "source_ip": incident.Source, "reason": "protected_or_out_of_scope", "actor": "policy", "action": "none",
		})
		return
	}
	job.phase = "pending"
	a.emit("soar.shadow_preview", incident.Run, "Simulação de impacto registrada antes do pedido de aprovação.", fields{
		"incident": incident.Incident, "source_ip": incident.Source, "target_ip": victimIP, "action": "http_block",
		"scope": "serviço HTTP da vítima", "ttl_seconds": int(blockTTL.Seconds()), "applied": false,
		"predicted_source_status": http.StatusForbidden, "predicted_control_status": http.StatusNoContent,
		"protected_ips": protectedIPs, "evidence_ids": incident.Evidence,
	})
	a.emit("soar.approval_requested", incident.Run, "Política validada. Contenção aguarda decisão do analista.", fields{
		"incident": incident.Incident, "source_ip": incident.Source, "protected_ips": protectedIPs,
		"ttl_seconds": int(blockTTL.Seconds()), "evidence_ids": incident.Evidence, "approval_id": approvalID(incident.Run),
	})
}

func validSeverity(value string) bool {
	return value == "alta" || value == "media" || value == "baixa"
}

func (a *appliance) applyTriagePolicy(job *workflow, severity string) {
	if severity == "alta" && job.incident.ChainComplete {
		a.requestApproval(job)
		return
	}
	job.phase = "monitoring"
	reason := "severity_below_high"
	if severity == "alta" {
		reason = "insufficient_evidence"
	}
	a.emit("soar.monitor_only", job.incident.Run, "Caso registrado para acompanhamento; política manteve o serviço acessível.", fields{
		"incident": job.incident.Incident, "severity": severity, "reason": reason, "action": "monitor",
	})
}

func (a *appliance) completeManualTriage(job *workflow, args []string) {
	incident := job.incident
	if len(args) == 2 && validSeverity(args[0]) {
		raw, err := base64.RawURLEncoding.DecodeString(args[1])
		reason := strings.TrimSpace(string(raw))
		if err == nil && utf8.Valid(raw) && len(raw) <= 1200 && utf8.RuneCountInString(reason) >= 3 && utf8.RuneCountInString(reason) <= 300 {
			severity := args[0]
			a.emit("soar.manual_triaged", incident.Run, "Analista classificou os registros selecionados.", fields{
				"actor": operator, "incident": incident.Incident, "severity": severity, "justification": reason, "evidence_ids": incident.Evidence,
			})
			a.applyTriagePolicy(job, severity)
			return
		}
	}
	a.emit("soar.triage_rejected", incident.Run, "Selecione uma severidade e escreva uma justificativa de 3 a 300 caracteres.", nil)
}

func (a *appliance) operatorCommand(run, action string, args []string) {
	a.mu.Lock()
	job := a.incidents[run]
	if job == nil {
		a.mu.Unlock()
		return
	}
	incident := job.incident
	request := decision{run, incident.Incident, incident.Source, operator}
	switch {
	case action == "llm-result" && job.phase == "awaiting-llm" && len(args) == 1:
		a.receiveLLM(job, args[0])
	case action == "manual-triage" && job.phase == "triage" && incident.Mode == "manual":
		a.completeManualTriage(job, args)
	case action == "reject" && job.phase == "pending":
		job.phase = "rejected"
		a.emit("soar.approval_rejected", run, "Analista rejeitou a contenção. Nenhum bloqueio foi aplicado.", fields{
			"actor": operator, "incident": incident.Incident, "evidence_ids": incident.Evidence, "action": "deny_http_block", "approval_id": approvalID(run),
		})
	case action == "approve" && job.phase == "pending":
		job.phase = "applying"
		a.emit("soar.approval_granted", run, "Analista autorizou o bloqueio temporário.", fields{
			"actor": operator, "incident": incident.Incident, "evidence_ids": incident.Evidence, "action": "approve_http_block",
			"approval_id": approvalID(run), "source_ip": incident.Source, "target_ip": victimIP, "ttl_seconds": int(blockTTL.Seconds()),
		})
		a.mu.Unlock()
		a.applyDecision(job, request)
		return
	case action == "rollback" && job.phase == "contained":
		a.emit("soar.rollback_requested", run, "Analista solicitou desbloqueio.", fields{"actor": operator, "incident": incident.Incident,
			"action": "request_http_unblock", "approval_id": approvalID(run), "source_ip": incident.Source, "target_ip": victimIP})
		a.mu.Unlock()
		if err := send(victimIP, "/rollback", request); err != nil {
			a.fail(run, err)
			return
		}
		a.mu.Lock()
		job.phase = "released"
	}
	a.mu.Unlock()
}

func (a *appliance) applyDecision(job *workflow, request decision) {
	run := request.Run
	if err := send(victimIP, "/contain", request); err != nil {
		a.mu.Lock()
		job.phase = "failed"
		a.mu.Unlock()
		a.fail(run, err)
		return
	}
	a.mu.Lock()
	job.phase = "contained"
	a.mu.Unlock()
	a.emit("soar.contained", run, "SOAR recebeu a confirmação da vítima.", fields{"incident": request.Incident, "source_ip": request.Source})
	response, err := client.Get("http://" + victimIP + ":8080/control")
	if err != nil {
		a.fail(run, err)
	} else {
		response.Body.Close()
		if response.StatusCode == http.StatusNoContent {
			a.emit("soar.control_allowed", run, "A origem de controle segue permitida.", fields{"source_ip": soarIP, "http_status": 204})
		} else {
			a.fail(run, fmt.Errorf("sonda de controle respondeu HTTP %d", response.StatusCode))
		}
	}
	a.emit("soar.ticket", run, "Ticket simulado criado com evidências e decisão do analista.", fields{
		"incident": request.Incident, "ticket": "TKT-" + run, "status": "contido", "actor": operator,
	})
	a.emit("soar.notification", run, "Notificação local simulada em #soc-alertas.", fields{
		"incident": request.Incident, "channel": "#soc-alertas", "delivery": "local",
	})
}
