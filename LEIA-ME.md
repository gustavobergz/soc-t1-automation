# Autonomous SOC Tier 1

Laboratório de demonstração adaptado ao guia técnico enviado. Quatro VMs Linux inicializam como convidados do VirtualBox ou do v86. O programa Go representa os papéis de Wazuh Manager/Agent e de um playbook n8n. Autenticação, reputação, ticket, notificação e a triagem padrão são simulados. O tráfego entre as VMs e a recusa no serviço HTTP da vítima ocorrem dentro do laboratório. A implantação de Wazuh Manager, Dashboard e Agent com telemetria real, do workflow n8n e do firewall ou Active Response faz parte da etapa de integração. [Wazuh Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html) · [Aprovação com o nó Wait do n8n](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.wait/)

## Abrir no VirtualBox

1. Abra **INICIAR VIRTUALBOX.cmd**. O iniciador cadastra as quatro VMs no grupo **SOC Tier 1 Demo** se necessário, inicia o grupo e abre o painel em `http://127.0.0.1:8771`.
2. Mantenha a janela do iniciador aberta e aguarde os quatro cartões indicarem **Online**. Use **Exportar JSONL** antes de fechar a sessão para guardar a auditoria e as medições.
3. Para encerrar, feche o iniciador e desligue as quatro VMs pelo VirtualBox. Também é possível executar `VirtualBox.ps1 -Mode Stop` no PowerShell.

O iniciador para Windows usa VirtualBox, Node.js e a ISO incluída em `lab/runtime/SOC-Tier1.iso`. Cada VM usa 384 MB de RAM, 1 vCPU e o snapshot **Base isolada**. O sistema e o estado do laboratório são carregados em memória. Para copiar o projeto, mantenha o painel, os iniciadores e as pastas `lab` e `logs` juntos. Em outro computador, use o iniciador da pasta de destino para registrar as VMs.

**Contingência.** Abra `index.html` diretamente no Chrome ou Edge para rodar as quatro VMs no navegador com v86. A faixa superior identifica qual ambiente está em uso. `logs/soc-demo.jsonl` pode ser apresentado como evidência de uma execução anterior.

## Topologia

```text
Atacante .30  ── tentativas e sondas ──► Endpoint .20 ── eventos ──► SIEM .10
                                             ▲                         │
                                             │                         ▼
                                     bloqueio / rollback ◄──────── SOAR .40
                                                                       ▲
                                                             aprovação no painel
```

As quatro VMs ficam na rede interna `SOC-TIER1-DEMO`, faixa `10.77.0.0/24`, sem gateway. O painel se comunica com o VirtualBox por portas seriais virtuais e só é servido em `127.0.0.1`. Os endereços `10.77.0.10`, `.20` e `.40` são protegidos pela política. A contenção do endereço de teste `.30` é limitada ao serviço da vítima e expira após 45 segundos.

## Roteiro de oito minutos

| Tempo | O que mostrar |
| --- | --- |
| 0–2 min | Apresente o abuso de credenciais e a fadiga de alertas. Mostre o grupo de VMs e a rede interna. |
| 2–4 min | Execute **Rodada manual**. Abra os detalhes dos eventos, marque as evidências individualmente e use **Ver marcadas** para conferir a seleção. Clique em **Identificar incidente**, escolha Alta, Média ou Baixa e escreva uma justificativa. Para demonstrar o bloqueio, selecione pelo menos cinco falhas, o login aceito e `sudo -l`, classifique como Alta e aprove a contenção. Use **Desbloquear agora** para liberar a próxima rodada. |
| 4–6 min | Execute **Assistida · IA simulada**. Mostre a regra 100501, a reputação sintética e **Ver triagem em JSON**. As duas rodadas reproduzem oito falhas de SSH, um login aceito e uma consulta `sudo -l` na conta fictícia `soclab`. |
| 6–7 min | Antes de aprovar, mostre a sonda atacante em HTTP 204. Clique em **Aprovar bloqueio**. O atacante recebe HTTP 403, a sonda de controle continua em HTTP 204 e o ticket é registrado. Use o desbloqueio manual ou aguarde a expiração e a sonda HTTP 204. |
| 7–8 min | Clique em **Avaliar detector**, mostre FP, FN e os limites da amostra. Compare as medições e abra a trilha da rodada para mostrar quem aprovou, horário e evidências. |

## Investigar 205.000 eventos

1. Abra **Investigar logs**. A versão hospedada carrega a base automaticamente. Na versão local, clique em **Carregar base de exemplo**. Se abriu `index.html` diretamente, escolha `logs/soc-investigacao-205k.jsonl.gz` no seletor. **Importar logs** também aceita outros arquivos JSONL, com ou sem gzip.
2. Combine busca por texto, severidade do evento, tipo, IP, usuário, host e período em UTC. O resultado é paginado em 50 ou 100 registros. Clique no tipo do evento para ler o JSON original. O botão **Filtrar por este IP** abre uma nova consulta para a origem do registro.
3. Marque os eventos relevantes nas caixas de seleção ou pelo detalhe. **Só evidências** mostra os registros marcados que também correspondem aos filtros atuais. A lista lateral reúne todas as marcações do caso, inclusive as que ficaram fora do filtro ou da página atual.
4. Dê um título ao caso, escolha a severidade e registre a justificativa. O painel salva os casos neste navegador e exporta as evidências selecionadas no formato original em **Exportar caso JSON**. Casos do explorador são locais e ficam separados da política de contenção ao vivo.

| Ponto de partida | O que investigar |
| --- | --- |
| `198.51.100.27` | Oito falhas de SSH, login aceito e `sudo -l` para `soclab` em `financeiro-07`. |
| `203.0.113.88` | Nove falhas de SSH no mesmo host, sem login aceito na sequência. |
| `192.0.2.144` | Uma falha, um login aceito e o encerramento da sessão, para comparar com os outros padrões. |

A base mistura cenários com atividade sintética de SSH, DNS, HTTP, firewall e processos. A severidade exibida na tabela é o nível do registro. A severidade do caso é uma decisão do analista. O fluxo de filtros e detalhes foi inspirado pelo Elastic Security, e o vínculo de registros a casos foi inspirado pela investigação do Microsoft Sentinel. [Elastic Security](https://www.elastic.co/docs/solutions/security/investigate/discover-security) · [Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/investigate-incidents)

## Evidências e política

- O SIEM registra ID, horário UTC do evento, IP de origem, conta, tipo, host e resultado da autenticação. A janela de 120 segundos limita as falhas. O protótipo usa limites independentes de 60 segundos da última falha qualificada até o login e de 60 segundos do login até a consulta de privilégios. A sequência é agrupada por origem, conta e host. A coleta descarta passos repetidos ou fora de ordem.
- A inteligência de ameaças usa uma pontuação sintética no formato de referência do AbuseIPDB. O endereço privado do laboratório fica fora de consultas ao AbuseIPDB e ao VirusTotal. O mapeamento associa as falhas a T1110.001 e o possível abuso de conta local a T1078.003. `sudo -l` é uma consulta de permissões. T1068 exige evidência de exploração de uma vulnerabilidade. [AbuseIPDB](https://docs.abuseipdb.com/) · [VirusTotal](https://docs.virustotal.com/reference/ip-info) · [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/)
- A triagem automática recebe contagem de falhas, indicadores de login e consulta, reputação simulada e IDs de evidência. Textos brutos, IP, usuário e host ficam fora do prompt. O validador rejeita campos extras ou duplicados, IDs inventados, técnicas e recomendações fora da lista. O JSON auditado guarda origem, versão do modelo, prompt versionado, horário, entrada, validação e resultado. Saída inválida ou indisponibilidade impedem o bloqueio. O [README](README.md#triagem-com-um-modelo-local) mostra como ativar o Ollama opcional.
- O operador fictício `analista-demo` pode registrar Alta, Média ou Baixa. Média, Baixa e Alta sem evidência da sequência completa seguem para acompanhamento. Alta com a sequência completa habilita aprovação humana. A vítima aplica o prazo de 45 s localmente. O painel mostra a expiração em UTC e vincula aprovação, bloqueio e reversão pelo campo `approval_id`. O evento de aprovação inclui autor, horário, ação, IP de origem, alvo e IDs das evidências.

## Revisão antes da decisão

Em **Operação ao vivo**, execute **Assistida · IA simulada** e abra **Revisar incidente** quando a rodada pedir aprovação. O **Attack Replay** lê os registros existentes. Use reprodução, pausa, avanço ou busca de posição para acompanhar os horários UTC. O **Evidence Gap Detector** aponta, por exemplo, a falta de telemetria após `sudo -l` ou de um registro de mudança autorizada.

O **False Positive Challenger** procura contraprovas com regras locais. Na opção Ollama, a revisão pode incorporar uma segunda saída validada, usando apenas dados normalizados e os valores da classificação inicial. O **Shadow Mode** registra o HTTP 403 previsto para a origem e o HTTP 204 previsto para o controle, sem tocar no serviço. O playbook registra a previsão antes de emitir o pedido de aprovação. **Simular impacto** permite repetir a análise; nas rodadas da sessão, a previsão também entra no JSONL exportado.

O **SOC Memory** compara a ordem dos eventos, o host, a conta e as técnicas. Encerrar uma investigação com uma conclusão revisada ou salvar a conclusão de uma rodada alimenta a memória neste navegador. Os exemplos fictícios aparecem identificados enquanto não houver resoluções revisadas semelhantes. A memória sugere o que conferir e não altera a classificação ou a aprovação.

O **Attack Story** agrupa falhas consecutivas da mesma origem, conta e host. Cada etapa abre os registros que a sustentam. O **Incident DNA** assina a sequência, as técnicas e os ativos e compara assinaturas na memória, inclusive quando o IP muda. O **Decision Receipt** exporta em JSON a regra, a justificativa, os IDs, o modelo, o prompt e a decisão humana ou da política, quando registrados.

Em **Pergunte aos registros**, tente “Quais IPs tiveram mais tentativas de login em 2026-11-09?” ou “Por que este incidente recebeu severidade alta?”. A primeira consulta usa a base carregada e a segunda usa a triagem da rodada selecionada. O painel responde com consultas estruturadas locais. O **Behavioral Fingerprint** usa logins aceitos anteriores da mesma conta, exige pelo menos 12 e marca como raro um horário com menos de 5% das ocorrências. Para experimentar o perfil, abra **SOC Arena**, escolha **Login fora da janela**, envie o cenário ao replay e clique em **Comparar com a base**.

O **SOC Pulse** soma 18, 9 ou 4 pontos por incidente aberto de nível alto, médio ou baixo, e 2 para itens sem nível. Cada ativo distinto soma 4 pontos e cada aprovação pendente soma 8. A pontuação é limitada a 100. O escopo é a sessão ao vivo e os casos locais em investigação. Encerrar um caso ou registrar a conclusão de uma rodada finalizada retira seu peso. O histórico de exemplo e os exercícios da **SOC Arena** ficam fora da pontuação.

## Métricas e exportação

Cada linha do JSONL é um objeto. Agrupe por `run` e filtre por `event` ou `vm`. O painel exibe os eventos pela ordem de recebimento e preserva o horário UTC da VM. Em `panel.metrics`, os valores são inteiros em milissegundos ou `null` quando a etapa não ocorreu. A tabela usa o relógio monotônico do painel para manter a mesma referência entre VMs.

| Medida | Início → fim |
| --- | --- |
| Detecção | Início da reprodução → identificação pelo analista ou pela regra |
| Triagem | Identificação → triagem registrada |
| Aprovação | Pedido de aprovação → decisão de aprovar |
| Resposta | Identificação (início do tratamento) → bloqueio aplicado, incluindo a espera pelo analista |
| MTTR | Média da resposta nas rodadas da sessão que tiveram bloqueio aplicado, separada por manual e assistido |
| Automação elegível | Rodadas assistidas com triagem automática validada ÷ rodadas assistidas correlacionadas que chegaram à triagem. A contenção continua sujeita à aprovação |
| FP e FN | Detector executado sobre oito cenários sintéticos rotulados. FPR = FP ÷ (FP + VN). FNR = FN ÷ (FN + VP) |

O exemplo incluído vem de uma validação do fluxo em laboratório. Os tempos refletem a execução de teste, inclusive o intervalo dos cliques. A avaliação rotulada inclui uma rotina autorizada que dispara a regra e abusos que a regra deixa passar. Esse conjunto pequeno mede o detector em cenários controlados. Ele deixa em aberto a precisão em produção, a qualidade da triagem do modelo real e o desempenho do analista humano.

## Imagens de inicialização

A ISO usa Alpine Linux 3.24.4, o kernel Alpine `linux-virt` 6.18.62 e ISOLINUX. O aplicativo e os empacotadores ficam em `lab`. A contingência usa o Buildroot Linux 6.8 distribuído pelo v86. [Alpine Linux](https://www.alpinelinux.org/downloads/) · [v86](https://github.com/copy/v86)
