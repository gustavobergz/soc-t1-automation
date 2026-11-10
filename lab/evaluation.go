package main

import (
	"fmt"
	"time"
)

type scenario struct {
	name         string
	malicious    bool
	failures     []int
	login        int
	sudo         int
	otherAccount bool
}

var scenarios = []scenario{
	{"Abuso completo", true, []int{0, 3, 6, 9, 12}, 15, 25, false},
	{"Janelas independentes", true, []int{0, 30, 60, 90, 120}, 180, 240, false},
	{"Credencial válida sem falhas", true, nil, 0, 15, false},
	{"Abuso com consulta fora da janela", true, []int{0, 3, 6, 9, 12}, 15, 76, false},
	{"Login administrativo comum", false, []int{0}, 3, -1, false},
	{"Rotina autorizada após erros", false, []int{0, 3, 6, 9, 12}, 15, 25, false},
	{"Falhas dispersas", false, []int{0, 30, 60, 90, 121}, 123, 124, false},
	{"Contas distintas", false, []int{0, 3, 6, 9, 12}, 15, 25, true},
}

func (s scenario) replay() []signal {
	base := time.Unix(1800000000, 0).UTC()
	var signals []signal
	appendEvent := func(kind string, offset int, username string) {
		if offset < 0 {
			return
		}
		step := len(signals) + 1
		signals = append(signals, signal{Run: "SOC-001", Mode: "auto", Step: step, ID: fmt.Sprintf("SOC-001-%02d", step),
			Source: attackIP, User: username, Host: endpoint, Kind: kind, At: base.Add(time.Duration(offset) * time.Second)})
	}
	for _, offset := range s.failures {
		appendEvent("ssh.failed", offset, account)
	}
	username := account
	if s.otherAccount {
		username = "outra-conta"
	}
	appendEvent("ssh.accepted", s.login, username)
	appendEvent("sudo.attempt", s.sudo, username)
	return signals
}

func detects(signals []signal) bool {
	groups := make(map[string][]signal)
	for _, event := range signals {
		key := correlationKey(event)
		groups[key] = append(groups[key], event)
		if event.Kind == "sudo.attempt" && summarize(groups[key]).ChainComplete {
			return true
		}
	}
	return false
}

func (a *appliance) evaluateDetector() {
	counts := map[string]int{"tp": 0, "tn": 0, "fp": 0, "fn": 0}
	results := make([]fields, 0, len(scenarios))
	for _, test := range scenarios {
		predicted := detects(test.replay())
		key := "tn"
		switch {
		case test.malicious && predicted:
			key = "tp"
		case test.malicious:
			key = "fn"
		case predicted:
			key = "fp"
		}
		counts[key]++
		results = append(results, fields{"scenario": test.name, "ground_truth": test.malicious, "detected": predicted, "outcome": key})
	}
	a.emit("siem.benchmark", "", "Detector executado sobre oito cenários sintéticos rotulados.", fields{
		"suite": "credential-abuse-v1", "counts": counts, "cases": results,
		"false_positive_rate": float64(counts["fp"]) / float64(counts["fp"]+counts["tn"]),
		"false_negative_rate": float64(counts["fn"]) / float64(counts["fn"]+counts["tp"]),
	})
}
