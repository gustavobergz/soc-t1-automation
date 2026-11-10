package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	managerIP = "10.77.0.10"
	victimIP  = "10.77.0.20"
	attackIP  = "10.77.0.30"
	soarIP    = "10.77.0.40"
	account   = "soclab"
	endpoint  = "endpoint-01"
	threshold = 5
	window    = 120 * time.Second
)

type fields map[string]any

type signal struct {
	Run    string    `json:"run"`
	Mode   string    `json:"mode"`
	Step   int       `json:"step"`
	Kind   string    `json:"kind"`
	Source string    `json:"source_ip,omitempty"`
	User   string    `json:"user,omitempty"`
	Host   string    `json:"host,omitempty"`
	Raw    string    `json:"raw,omitempty"`
	ID     string    `json:"event_id,omitempty"`
	At     time.Time `json:"timestamp"`
	Result string    `json:"auth_result,omitempty"`
}

type alert struct {
	Run           string   `json:"run"`
	Incident      string   `json:"incident"`
	Source        string   `json:"source_ip"`
	User          string   `json:"user"`
	Host          string   `json:"host"`
	Failures      int      `json:"failures"`
	Mode          string   `json:"mode"`
	Evidence      []string `json:"evidence_ids"`
	ChainComplete bool     `json:"chain_complete"`
}

type caseState struct {
	signals    []signal
	dispatched bool
}

type appliance struct {
	role string
	mu   sync.Mutex

	activeRun string
	blocked   *block
	cases     map[string]*caseState
	incidents map[string]*workflow
}

var (
	client = &http.Client{Timeout: 4 * time.Second}
	runID  = regexp.MustCompile(`^SOC-[0-9]{3,}$`)
)

func (a *appliance) emit(event, run, message string, detail fields) {
	record := fields{
		"timestamp": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"vm":        a.role, "event": event, "message": message, "synthetic": true,
	}
	if run != "" {
		record["run"] = run
	}
	for key, value := range detail {
		record[key] = value
	}
	data, err := json.Marshal(record)
	if err == nil {
		fmt.Printf("@@SOC@@%s\n", data)
	}
}

func (a *appliance) fail(run string, err error) {
	a.emit("lab.error", run, err.Error(), nil)
}

func remoteIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func post(ip, path string, payload any) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	response, err := client.Post("http://"+ip+":8080"+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode, nil
}

func send(ip, path string, payload any) error {
	code, err := post(ip, path, payload)
	if err != nil {
		return err
	}
	if code != http.StatusNoContent {
		return fmt.Errorf("%s%s respondeu HTTP %d", ip, path, code)
	}
	return nil
}

func decode(w http.ResponseWriter, r *http.Request, source string, out any) bool {
	if remoteIP(r) != source {
		http.Error(w, "origem recusada", http.StatusForbidden)
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil || decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "evento invalido", http.StatusBadRequest)
		return false
	}
	return true
}

func (a *appliance) attempt(w http.ResponseWriter, r *http.Request) {
	var event signal
	if !decode(w, r, attackIP, &event) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if event.Run == "" || event.Run != a.activeRun {
		http.Error(w, "rodada desconhecida", http.StatusConflict)
		return
	}
	event.Source, event.User, event.Host = remoteIP(r), account, endpoint
	if a.blocked != nil && !time.Now().Before(a.blocked.expires) {
		a.releaseBlock("expiration", "policy")
	}
	if a.blocked != nil && a.blocked.request.Source == event.Source {
		a.emit("endpoint.denied", event.Run, "O serviço de demonstração recusou a origem contida.", fields{"source_ip": event.Source, "http_status": 403})
		http.Error(w, "origem contida", http.StatusForbidden)
		return
	}
	if event.Kind == "ssh.probe" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	event.ID = fmt.Sprintf("%s-%02d", event.Run, event.Step)
	event.At = time.Now().UTC()
	switch event.Kind {
	case "ssh.failed":
		event.Result = "failure"
		event.Raw = fmt.Sprintf("%s sshd[%d]: Failed password for %s from %s port 51000 ssh2", endpoint, 1800+event.Step, account, event.Source)
	case "ssh.accepted":
		event.Result = "success"
		event.Raw = fmt.Sprintf("%s sshd[1820]: Accepted password for %s from %s port 51000 ssh2", endpoint, account, event.Source)
	case "sudo.attempt":
		event.Raw = fmt.Sprintf("%s sudo[1821]: %s : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/sudo -l", endpoint, account)
	default:
		http.Error(w, "tipo invalido", http.StatusBadRequest)
		return
	}
	a.emit("endpoint.observed", event.Run, event.Raw, eventFields(event))
	if err := send(managerIP, "/event", event); err != nil {
		a.fail(event.Run, err)
		http.Error(w, "coleta indisponivel", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func eventFields(event signal) fields {
	return fields{
		"event_id": event.ID, "event_time": event.At, "event_type": event.Kind,
		"kind": event.Kind, "step": event.Step, "source_ip": event.Source, "username": event.User,
		"user": event.User, "host": event.Host, "raw": event.Raw, "mode": event.Mode, "auth_result": event.Result,
	}
}

func (a *appliance) collect(w http.ResponseWriter, r *http.Request) {
	var event signal
	if !decode(w, r, victimIP, &event) {
		return
	}
	if !runID.MatchString(event.Run) || event.Step < 1 || event.ID != fmt.Sprintf("%s-%02d", event.Run, event.Step) ||
		event.At.IsZero() || event.At.After(time.Now().Add(5*time.Second)) || time.Since(event.At) > window {
		http.Error(w, "identidade ou horario do evento invalido", http.StatusBadRequest)
		return
	}
	a.collectSignal(event)
	w.WriteHeader(http.StatusNoContent)
}

func (a *appliance) collectSignal(event signal) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := strings.Join([]string{event.Run, event.Host, event.Source, event.User}, "/")
	state := a.cases[key]
	if state == nil {
		state = &caseState{}
		a.cases[key] = state
	}
	if len(state.signals) > 0 && (event.Step <= state.signals[len(state.signals)-1].Step || event.At.Before(state.signals[len(state.signals)-1].At)) {
		a.emit("siem.discarded", event.Run, "Evento duplicado ou fora de ordem descartado.", fields{"event_id": event.ID})
		return
	}
	state.signals = append(state.signals, event)
	a.emit("siem.raw", event.Run, event.Raw, eventFields(event))
	if event.Mode != "manual" && event.Kind == "sudo.attempt" && !state.dispatched {
		incident := summarize(state.signals)
		if incident.ChainComplete {
			a.dispatch(state, incident, "siem.correlated")
		}
	}
}

func summarize(signals []signal) alert {
	first := signals[0]
	incident := alert{Run: first.Run, Incident: "INC-" + first.Run, Source: first.Source, User: first.User, Host: first.Host, Mode: first.Mode}
	var failures []time.Time
	accepted := false
	for _, event := range signals {
		incident.Evidence = append(incident.Evidence, event.ID)
		for len(failures) > 0 && event.At.Sub(failures[0]) > window {
			failures = failures[1:]
		}
		switch event.Kind {
		case "ssh.failed":
			incident.Failures++
			failures = append(failures, event.At)
			accepted = false
		case "ssh.accepted":
			accepted = len(failures) >= threshold
		case "sudo.attempt":
			incident.ChainComplete = incident.ChainComplete || (accepted && len(failures) >= threshold)
		}
	}
	return incident
}

func (a *appliance) identify(run string, ids []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(ids) <= 30 {
		for _, state := range a.cases {
			var selected []signal
			for _, event := range state.signals {
				if event.Run == run && event.Mode == "manual" && slices.Contains(ids, event.ID) {
					selected = append(selected, event)
				}
			}
			if len(selected) > 0 && len(selected) == len(ids) {
				a.dispatch(state, summarize(selected), "siem.manual_detected")
				return
			}
		}
	}
	a.emit("siem.selection_rejected", run, "Selecione evidências da mesma origem, conta e host nesta rodada.", nil)
}

func (a *appliance) dispatch(state *caseState, incident alert, event string) {
	if state.dispatched {
		return
	}
	state.dispatched = true
	detail := fields{"incident": incident.Incident, "failures": incident.Failures, "source_ip": incident.Source,
		"username": incident.User, "host": incident.Host, "evidence_ids": incident.Evidence, "mode": incident.Mode, "chain_complete": incident.ChainComplete}
	message := "Analista identificou o incidente a partir dos registros selecionados."
	if event == "siem.correlated" {
		detail["rule_id"], detail["window_seconds"] = 100501, int(window.Seconds())
		message = "Identificada sequência de falhas de SSH, login aceito e consulta sudo -l."
	}
	a.emit(event, incident.Run, message, detail)
	go func() {
		if err := send(soarIP, "/playbook", incident); err != nil {
			a.fail(incident.Run, err)
		}
	}()
}

func (a *appliance) runAttack(mode, run string) error {
	a.emit("attack.started", run, "Início da reprodução de tentativas contra o serviço de demonstração.", fields{"mode": mode, "source_ip": attackIP, "target_ip": victimIP})
	for step := 1; step <= 10; step++ {
		kind := "ssh.failed"
		if step == 9 {
			kind = "ssh.accepted"
		}
		if step == 10 {
			kind = "sudo.attempt"
		}
		event := signal{Run: run, Mode: mode, Step: step, Kind: kind}
		if err := send(victimIP, "/attempt", event); err != nil {
			return err
		}
		a.emit("attack.replayed", run, "Evento de ataque simulado reproduzido.", fields{"step": step, "kind": kind, "target_ip": victimIP})
		time.Sleep(220 * time.Millisecond)
	}
	return nil
}

func (a *appliance) probe(run, phase string) {
	code, err := post(victimIP, "/attempt", signal{Run: run, Kind: "ssh.probe"})
	if err != nil {
		a.fail(run, err)
		return
	}
	a.emit("attack.probe", run, fmt.Sprintf("Sonda da origem atacante recebeu HTTP %d.", code),
		fields{"http_status": code, "phase": phase, "source_ip": attackIP, "target_ip": victimIP})
}

func (a *appliance) command(line string) {
	args := strings.Fields(line)
	if len(args) == 1 && args[0] == "hello" {
		a.ready()
		return
	}
	if len(args) < 2 || !runID.MatchString(args[1]) {
		return
	}
	run := args[1]
	switch {
	case a.role == "victim" && args[0] == "prepare":
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.blocked != nil && time.Now().Before(a.blocked.expires) {
			a.fail(run, fmt.Errorf("há um bloqueio ativo; aguarde a expiração ou faça o rollback"))
			return
		}
		if a.blocked != nil {
			a.releaseBlock("expiration", "policy")
		}
		a.activeRun = run
		a.emit("endpoint.prepared", run, "Serviço de demonstração liberado para a nova rodada.", nil)
	case a.role == "attacker" && args[0] == "run" && len(args) == 3:
		mode := args[2]
		if mode != "manual" && mode != "auto" && mode != "failure" {
			return
		}
		if err := a.runAttack(mode, run); err != nil {
			a.fail(run, err)
		}
		a.emit("attack.finished", run, "Reprodução concluída.", nil)
	case a.role == "attacker" && args[0] == "probe" && len(args) == 3:
		a.probe(run, args[2])
	case a.role == "manager" && args[0] == "manual-detect" && len(args) == 3:
		a.identify(run, strings.Split(args[2], ","))
	case a.role == "soar":
		a.operatorCommand(run, args[0], args[2:])
	}
}

func (a *appliance) ready() {
	ip := map[string]string{"manager": managerIP, "victim": victimIP, "attacker": attackIP, "soar": soarIP}[a.role]
	a.emit("vm.ready", "", "VM inicializada na rede virtual isolada.", fields{"ip": ip, "cidr": "10.77.0.0/24"})
}

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: soc-lab ROLE IP")
	}
	role, ip := os.Args[1], os.Args[2]
	a := &appliance{role: role, cases: make(map[string]*caseState), incidents: make(map[string]*workflow)}
	mux := http.NewServeMux()
	switch role {
	case "manager":
		mux.HandleFunc("POST /event", a.collect)
	case "victim":
		mux.HandleFunc("POST /attempt", a.attempt)
		mux.HandleFunc("POST /contain", a.contain)
		mux.HandleFunc("POST /rollback", a.rollback)
		mux.HandleFunc("GET /control", func(w http.ResponseWriter, r *http.Request) {
			if remoteIP(r) != soarIP {
				http.Error(w, "origem recusada", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	case "soar":
		mux.HandleFunc("POST /playbook", a.playbook)
	case "attacker":
	default:
		log.Fatal("unknown role: " + strconv.Quote(role))
	}
	if role != "attacker" {
		listener, err := net.Listen("tcp4", ip+":8080")
		if err != nil {
			log.Fatal(err)
		}
		server := &http.Server{Handler: mux, ReadHeaderTimeout: 4 * time.Second, WriteTimeout: 8 * time.Second}
		go func() { log.Fatal(server.Serve(listener)) }()
	}
	a.ready()
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		a.command(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	select {}
}
