# Autonomous SOC Tier 1

Laboratório de SOC para investigar abuso de credenciais, correlacionar evidências e demonstrar contenção com aprovação humana. Os eventos, o enriquecimento e a triagem assistida padrão são simulados. A contenção é aplicada somente ao serviço HTTP de demonstração.

## Abrir em um clique

[**Abrir a demonstração no navegador**](https://gustavobergz.github.io/soc-t1-automation/)

- **Visão geral** reúne os indicadores da base carregada, os incidentes da demonstração e a topologia da rede isolada. Use **Ctrl+K** para buscar em qualquer área.
- **Investigar logs** abre o explorador com 205.000 eventos sintéticos. Filtre pelo IP `198.51.100.27` para encontrar oito falhas de autenticação, um login aceito e uma consulta de privilégios. Abra o JSON original, selecione as evidências e exporte o caso.
- **Operação ao vivo** inicia quatro VMs Linux isoladas no navegador. A rodada manual permite escolher as evidências, a severidade e a justificativa. A rodada assistida demonstra a correlação, a aprovação humana, o bloqueio por 45 segundos e a opção de desbloquear.
- **Método e auditoria** mostra o escopo em relação ao guia, a avaliação reproduzível do detector e o JSON de triagem, aprovação, contenção e reversão.
- **Análise de incidentes** permite reproduzir a trilha UTC, consultar contraprovas e lacunas, comparar casos encerrados e simular a contenção HTTP. Abra uma rodada, a trilha de exemplo ou um JSONL de auditoria para ver a história com evidências, a assinatura do incidente e o comprovante da triagem.
- **Ask Your SOC** consulta falhas de SSH por IP e explica a severidade registrada. As respostas usam consultas locais com escopo e referências. O perfil de acesso compara hora e host com logins anteriores da conta na base carregada.
- **Visão geral** inclui o SOC Pulse, que mostra o risco de 0 a 100 e os fatores que alteraram a pontuação. Na **SOC Arena**, pratique a classificação e a escolha da evidência decisiva em três cenários fictícios.

## Rodar localmente

1. Baixe o projeto pelo botão **Code → Download ZIP** e extraia toda a pasta.
2. Abra **index.html** no Chrome ou Edge. Para usar o explorador, escolha `logs/soc-investigacao-205k.jsonl.gz` em **Carregar base de exemplo**.
3. Para usar o **VirtualBox no Windows**, tenha VirtualBox e Node.js instalados e abra **INICIAR VIRTUALBOX.cmd**. O iniciador registra as quatro VMs da demo e abre o painel local.

O [roteiro de oito minutos](LEIA-ME.md) inclui a topologia, o fluxo de aprovação e exemplos de investigação. O [log de validação](logs/soc-demo.jsonl) registra execuções anteriores. Os [componentes de terceiros](THIRD_PARTY_NOTICES.md) estão descritos separadamente.

## Triagem com um modelo local

O GitHub Pages e a rodada assistida padrão usam uma saída simulada que passa pelo mesmo validador do modelo. Para testar a inferência no VirtualBox, inicie o Ollama em modo local com um modelo já instalado e listado em `ollama list`. Informe a tag exata ao iniciar o painel. Exemplo no PowerShell com a tag do seu modelo instalada previamente:

```powershell
$env:SOC_OLLAMA_MODEL = 'qwen2.5:3b'
.\VirtualBox.ps1
```

Se o iniciador do VirtualBox já estiver aberto, feche-o antes de iniciar com essa configuração. Selecione **Assistida · Ollama local**. O conector usa `127.0.0.1:11434`, exige uma tag local sem variante de nuvem e envia apenas o incidente normalizado. Abra **Ver triagem em JSON** para inspecionar modelo, digest, versão do Ollama, prompt, resultado e validação. Indisponibilidade ou saída rejeitada mantém o serviço acessível. [API e saídas estruturadas do Ollama](https://docs.ollama.com/capabilities/structured-outputs)

O **False Positive Challenger** pode fazer uma segunda chamada ao modelo local. Ela recebe os mesmos campos normalizados e a classificação inicial em valores predefinidos. Quando a segunda saída não é válida ou está indisponível, a revisão usa regras locais. A contraprova é consultiva. A decisão de contenção continua com o analista.

## Base sintética

O arquivo `logs/soc-investigacao-205k.jsonl.gz` contém 205.000 objetos JSON, um por linha. O explorador lê o gzip diretamente. Para gerar uma cópia sem compressão, use `node lab/generate-logs.cjs`. Para reproduzir a versão compactada, use `node lab/generate-logs.cjs logs/soc-investigacao-205k.jsonl.gz`.
