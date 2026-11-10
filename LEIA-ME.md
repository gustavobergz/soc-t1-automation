# Autonomous SOC Tier 1

Laboratório de demonstração adaptado ao guia técnico enviado. Quatro VMs Alpine Linux reproduzem os papéis de Wazuh, endpoint, estação de teste e SOAR. A autenticação, a reputação, o LLM, o ticket e a notificação são simulados. O tráfego entre VMs e a restrição HTTP no serviço da vítima são reais dentro do laboratório.

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
| 4–6 min | Execute **Rodada assistida**. Mostre a regra 100501, a reputação sintética e a triagem estruturada. As duas rodadas reproduzem oito falhas de SSH, um login aceito e uma consulta `sudo -l` na conta fictícia `soclab`. |
| 6–7 min | Antes de aprovar, mostre a sonda atacante em HTTP 204. Clique em **Aprovar bloqueio**. O atacante recebe HTTP 403, a sonda de controle continua em HTTP 204 e o ticket é registrado. Use o desbloqueio manual ou aguarde a expiração e a sonda HTTP 204. |
| 7–8 min | Compare as medições, exporte o JSONL e mostre o **Explorador de logs** para demonstrar a investigação sobre uma base maior. |

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

- O SIEM registra ID, horário UTC do evento, IP de origem, conta, tipo, host e resultado da autenticação. A rodada assistida usa cinco ou mais falhas seguidas de login e consulta administrativa para a mesma origem, conta e host em até 120 segundos. A coleta descarta passos repetidos ou fora de ordem.
- A inteligência de ameaças usa uma pontuação sintética. O mapeamento de teste associa as falhas e a conta local a T1110.001 e T1078.003. A consulta `sudo -l` indica interesse em permissões e permanece registrada como evidência de consulta. [T1110.001](https://attack.mitre.org/techniques/T1110/001/) · [T1078.003](https://attack.mitre.org/techniques/T1078/003/)
- O SOAR registra modelo simulado, versão, prompt e resultado estruturado. A validação exige os IDs da evidência e o esquema esperado. Na rodada de falha, a ausência de triagem impede a aprovação e o bloqueio.
- O operador fictício `analista-demo` pode registrar Alta, Média ou Baixa. O SOAR guarda os IDs escolhidos e a justificativa na auditoria. Média, Baixa e Alta sem evidência da sequência completa seguem para acompanhamento. Alta com a sequência completa habilita aprovação humana. A vítima aplica a expiração localmente, inclusive se o painel for fechado.

## Métricas e exportação

Cada linha do JSONL é um objeto. Agrupe por `run` e filtre por `event` ou `vm`. O painel exibe os eventos pela ordem de recebimento e preserva o horário UTC da VM. Em `panel.metrics`, os valores são inteiros em milissegundos ou `null` quando a etapa não ocorreu. A tabela usa o relógio monotônico do painel para manter a mesma referência entre VMs.

| Medida | Início → fim |
| --- | --- |
| Detecção | Início da reprodução → identificação pelo analista ou pela regra |
| Triagem | Identificação → triagem registrada |
| Aprovação | Pedido de aprovação → decisão de aprovar |
| Resposta | Identificação → bloqueio aplicado, incluindo a espera pelo analista |

O exemplo incluído vem de uma validação do fluxo em laboratório. Os tempos refletem a execução de teste, inclusive o intervalo dos cliques. Para calcular médias experimentais, repita as rodadas nas mesmas condições e separe os tempos de detecção, triagem e aprovação. Medir falsos positivos e negativos requer um conjunto rotulado com casos benignos e maliciosos.

## Imagens de inicialização

A ISO usa Alpine Linux 3.24.4, o kernel Alpine `linux-virt` 6.18.62 e ISOLINUX. O aplicativo e os empacotadores ficam em `lab`. A contingência usa o Buildroot Linux 6.8 distribuído pelo v86. [Alpine Linux](https://www.alpinelinux.org/downloads/) · [v86](https://github.com/copy/v86)
