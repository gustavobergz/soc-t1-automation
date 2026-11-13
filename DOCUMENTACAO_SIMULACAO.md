# SOC Clínica — documentação da simulação

## O que o projeto demonstra

O SOC Clínica é um laboratório acadêmico de detecção, investigação e resposta a atividades suspeitas em uma clínica fictícia. Ele acompanha autenticação, acesso a prontuários, solicitações de exportação e alterações de permissões. A conta médica roubada é o cenário principal. Exportação indevida e mudança de privilégios ampliam a cobertura. Um plantão autorizado permite avaliar uma explicação legítima para um comportamento incomum.

Todos os usuários, pacientes, prontuários, escalas e autorizações são inventados. Os eventos de prontuário guardam referências fictícias e metadados de acesso. O conteúdo de consultas médicas, exames e diagnósticos fica fora do conjunto de dados.

O objetivo é mostrar como o analista chega a uma decisão apoiada por evidências e por uma IA executada localmente. O desempenho depende da cobertura dos logs, das regras, do modelo e da revisão humana.

## Componentes e fluxo de dados

| Componente | Responsabilidade |
| --- | --- |
| Reprodutor de atividade | Reproduz uma sequência previamente definida de eventos fictícios. |
| Aplicação da clínica | Gera auditoria de autenticação, prontuários, exportações e IAM. Aplica a suspensão temporária da sessão de teste. |
| Coletor e correlacionador | Normaliza registros, vincula conta, sessão e serviço e executa regras com janela de 120 segundos. |
| Triagem | Recebe contagens, indicadores e IDs de evidência. Produz severidade, explicação, incertezas e recomendações em JSON validado. |
| Revisão | Exibe contraprovas, lacunas, casos anteriores, impacto previsto e comprovante da decisão. |
| Analista | Seleciona evidências, revisa a severidade e autoriza ou rejeita a contenção. |
| Resposta | Suspende a sessão autorizada para contenção, verifica sondas e registra aprovação e reversão. |

A coleta e a correlação usam Go. O painel usa JavaScript. Quatro convidados Linux executam os papéis de SIEM, aplicação da clínica, reprodutor e SOAR, pelo VirtualBox ou pelo v86 no navegador. Wazuh e n8n são referências de arquitetura representadas pelo coletor e playbook próprios. A implantação dos produtos originais exige uma etapa adicional de integração com agentes e fontes reais.

A rede das VMs é interna, no segmento `10.77.0.0/24`. O host disponibiliza o painel local em `127.0.0.1:8771`. O conector de IA se comunica com `127.0.0.1:11434`. O banco lógico da investigação é o arquivo JSONL compactado. A memória revisada e os casos do analista ficam no armazenamento do navegador e podem ser exportados. O modelo recebe somente o incidente selecionado, independentemente do tamanho do arquivo histórico.

## Situações reproduzidas

| Cenário | Evidências | Resultado padrão da triagem simulada |
| --- | --- | --- |
| Conta médica roubada | Login em dispositivo desconhecido e fora da escala, 80 consultas sem vínculo de atendimento e pedido de exportação. | Alta. Solicitar aprovação para suspender a sessão. |
| Exportação indevida | Conta de recepção solicita 250 registros, e a aplicação recusa a operação por falta de autorização. | Média. Investigar a tentativa e manter acompanhamento. |
| Alteração de permissões | Conta de enfermagem recebe administrador sem mudança aprovada e acessa a área administrativa. | Alta. Solicitar aprovação para suspender a sessão. |
| Plantão autorizado | Registro de mudança autoriza plantão e exportação da mesma conta, sessão e serviço. | Baixa. A revisão contextual encaminha para acompanhamento. |

Os níveis acima são as prioridades operacionais calculadas pelas regras a partir das evidências. No modo simulado, a sugestão acompanha essa referência. O modelo real pode propor outra severidade. O painel mostra a prioridade da regra, a sugestão do modelo e o desacordo quando houver. A política usa a prioridade operacional e ainda exige aprovação humana para conter. Na rodada manual, o analista escolhe a severidade e fornece sua justificativa, sujeito às mesmas restrições de autorização.

No cenário principal, o gabarito informa que a credencial foi roubada. Os logs permitem levantar a hipótese e justificar uma investigação. Atribuir o acesso ao atacante ainda depende de confirmar a sessão com a titular. A Arena cobra essa distinção e aceita a classificação inconclusiva quando a pergunta é sobre a confirmação do comprometimento.

O pedido de exportação indica intenção ou tentativa. A recusa da aplicação confirma o resultado daquele pedido. Afirmar entrega de arquivo ou vazamento exige evidências adicionais, como conclusão da exportação e transferência dos dados.

## Logs e regras

A base `logs/clinica-investigacao-205k.jsonl.gz` contém exatamente 205.000 eventos. Ela mistura rotina da clínica e os quatro cenários. Cada linha descompactada é um objeto JSON independente. O cenário ao vivo resume as consultas a prontuários em eventos com contagem. A base histórica expande as consultas em registros individuais para permitir seleção e investigação uma a uma.

| Campo | Significado |
| --- | --- |
| `event_id`, `timestamp` | Identidade e horário UTC do registro. |
| `event_type` | Ação observada, como `auth.login`, `ehr.record_read` ou `iam.role_changed`. |
| `username`, `role` | Referência fictícia da conta e função na clínica. |
| `host`, `device_id` | Serviço auditado e estação fictícia de acesso. |
| `session_id`, `source_ip` | Sessão e origem utilizadas para vincular ações. |
| `patient_ref` | Referência fictícia, presente nas consultas individuais da base. |
| `clinical` | Contagem, vínculo de atendimento, autorização, escala e resultado da ação. |
| `scenario`, `synthetic` | Identificação do cenário e indicação explícita de dados simulados. |

Os pontos iniciais de busca são `MED-017`, `REC-004` e `ENF-009`. A busca de texto também consulta cenário, sessão e referência fictícia de prontuário. Os filtros de conta e tipo podem ser combinados com a busca. Para distinguir os dois cenários de MED-017, use as sessões `SES-MED-017` e `SES-PLANTAO-017` no JSON e as autorizações registradas.

| Regra | Condição |
| --- | --- |
| 110101 | Login em dispositivo desconhecido e fora da escala, pelo menos 50 consultas e solicitação de exportação na mesma sessão, em até 120 s após o login. |
| 110102 | Login seguido de pedido de pelo menos 50 registros e exportação negada na mesma sessão, em até 120 s. |
| 110103 | Login seguido de concessão de administrador e acesso administrativo na mesma sessão, em até 120 s. |

O plantão autorizado pode disparar a regra de comportamento. A triagem e a política consultam a autorização para explicar e restringir a resposta. Ausência de login, separação entre sessões ou atividade fora da janela podem impedir a correlação. O detector identifica apenas os padrões cobertos pelas regras e pelas fontes integradas.

A associação ATT&CK usa T1078 como hipótese de abuso de conta válida, T1213 como hipótese de coleta em repositório e T1098 para manipulação de permissões. Esses rótulos representam hipóteses ou ações compatíveis com o cenário. O protótipo preserva o mapeamento anterior de SSH ao selecionar o laboratório legado. [MITRE T1078](https://attack.mitre.org/techniques/T1078/), [MITRE T1213](https://attack.mitre.org/techniques/T1213/), [MITRE T1098](https://attack.mitre.org/techniques/T1098/)

## IA local e tratamento das informações

O modo público usa uma saída simulada identificada. No VirtualBox, a opção Ollama executa inferência no computador com um modelo já treinado. O configurador utiliza `qwen2.5:1.5b` por padrão. O primeiro download instala o Ollama e baixa os pesos. Depois de preparados os arquivos, as chamadas de inferência usam o servidor local.

A entrada contém o cenário, contagens, indicadores booleanos, técnicas permitidas e IDs de evidência. Os IDs referenciam os logs que permanecem no laboratório. Conta, sessão, origem, estação, prontuário, texto bruto e conteúdo clínico ficam fora da entrada do modelo.

O configurador liga o servidor a `127.0.0.1`, define `OLLAMA_NO_CLOUD=1` e mantém pesos e logs do serviço em `%LOCALAPPDATA%\SOC-Tier1`. O conector exige uma tag instalada localmente, rejeita modelos identificados como remotos e valida modelo, digest e versão do mecanismo. [Ollama no Windows](https://docs.ollama.com/windows), [modo local e recursos de nuvem](https://docs.ollama.com/faq)

A preparação para CPU utiliza a distribuição oficial do Ollama 0.40.16, com versão, endereço e SHA256 fixados em `lab/ollama-cpu.json`. O download de aproximadamente 46 MB contém o segmento do ZIP necessário aos binários CPU e ao diretório do arquivo. O instalador verifica o SHA256 desse segmento antes de extrair os arquivos. Essa verificação cobre o segmento utilizado. A reconstrução temporária ocupa aproximadamente 1,6 GB. O executável preparado também teve sua assinatura Authenticode validada neste computador. O próprio Ollama verifica os pesos durante o download do modelo, de aproximadamente 986 MB.

A resposta de triagem contém oito campos — tipo de suspeita, severidade, justificativa, IDs, técnicas, impacto, incerteza e recomendações. O validador rejeita campos extras ou duplicados, IDs inventados ou reordenados, técnicas incompatíveis e ações fora da lista. Falha da primeira triagem impede a contenção automática. A segunda chamada procura contraprovas e é consultiva. Se ela falhar, a contraprova usa regras locais. [Saídas estruturadas do Ollama](https://docs.ollama.com/capabilities/structured-outputs)

A validação de JSON verifica estrutura, referências e valores permitidos. A fidelidade das explicações aos fatos exige revisão humana. O painel apresenta **Fatos registrados**, gerados diretamente do resumo das evidências, ao lado da análise. Durante testes iniciais, o modelo confundiu pedido de exportação com exportação negada e divergiu das prioridades de referência. A versão `soc-clinic-3` do prompt acrescenta descrições em português geradas por código a partir dos indicadores e uma referência calculada pelas regras. A prioridade operacional é independente da sugestão do modelo, e o comprovante preserva as duas classificações. A segunda revisão usa o mesmo modelo e também exige conferência pelo analista.

Os dados são tratados como evidências. Textos brutos de logs e notas do analista ficam fora do prompt. A aplicação recebe apenas recomendações predefinidas e reserva a execução à política e à decisão humana. A inferência pode demorar mais em CPU. O sistema registra a duração observada, em vez de presumir resposta instantânea.

A execução local reduz a transmissão de informações a fornecedores externos. Uma implantação com pessoas reais ainda exige definir finalidade, base legal, acesso, retenção, segurança e responsabilidades. A simulação demonstra escolhas de arquitetura e controles, e sua documentação descreve o alcance desses controles. Dados de saúde vinculados a pessoas são sensíveis conforme o art. 5º da LGPD. Os arts. 6º e 46 tratam da necessidade e da segurança no tratamento. [Texto atualizado da LGPD](https://www2.camara.leg.br/legin/fed/lei/2018/lei-13709-14-agosto-2018-787077-normaatualizada-pl.html)

O repositório e o site público devem conter somente dados fictícios. Para uso real, a equipe deve manter as fontes operacionais em ambiente privado e revisar também notificações, exports, backups e armazenamento do navegador.

## Como executar

### Navegador

1. Abra a demonstração publicada no GitHub Pages.
2. Em **Análise de incidentes**, escolha uma rodada de referência e use o replay, as contraprovas, as lacunas e o comprovante.
3. Em **Investigar logs**, aguarde a base de 205 mil eventos e filtre pela conta ou tipo de evento. Marque registros individuais e exporte o caso.
4. Em **Operação ao vivo**, aguarde as quatro VMs, escolha o cenário e execute uma rodada manual ou assistida simulada.

### VirtualBox com IA local

1. Tenha VirtualBox e Node.js disponíveis no Windows e mantenha toda a pasta do projeto extraída.
2. Execute **CONFIGURAR IA LOCAL.cmd** uma vez. A preparação usa internet e alguns GB de armazenamento.
3. Execute **INICIAR COM IA LOCAL.cmd**. O iniciador abre as quatro VMs e o painel em `http://127.0.0.1:8771/`.
4. Em **Operação ao vivo**, selecione **Conta médica roubada** e **Assistida · Ollama local**.
5. Abra a triagem em JSON para conferir o modelo, o prompt, os fatos enviados e a validação.

O comando **INICIAR VIRTUALBOX.cmd** continua disponível para o modo simulado. É possível configurar outra tag instalada com `LocalAI.ps1 -Setup -Model 'sua-tag:local'` e iniciar o painel com a mesma configuração em PowerShell. As VMs de laboratório são identificadas pelo iniciador. Para encerrá-las, use `VirtualBox.ps1 -Mode Stop`.

## Roteiro de apresentação de oito minutos

1. **Um minuto** — apresente a clínica fictícia e o problema de acesso indevido a dados de saúde.
2. **Dois minutos** — execute a conta roubada e abra os registros de login, consultas e exportação. Mostre os indicadores enviados à triagem.
3. **Um minuto** — abra a revisão e explique o que falta confirmar antes de concluir comprometimento ou vazamento.
4. **Um minuto** — simule o impacto, aprove a suspensão e mostre a sessão suspeita em HTTP 403 e a sessão legítima em HTTP 204.
5. **Um minuto** — reverta a contenção e abra o comprovante da decisão e a auditoria.
6. **Um minuto** — execute a exportação negada e mostre a severidade média e o encaminhamento para acompanhamento.
7. **Um minuto** — compare alteração de permissões com plantão autorizado e apresente as limitações do experimento.

Prepare o modelo antes da apresentação. O replay permite apresentar rodadas já registradas quando o tempo disponível for curto.

## Resposta, auditoria e métricas

A contenção clínica suspende temporariamente a sessão de teste dentro do serviço HTTP do laboratório. Uma segunda sessão da mesma origem é usada para verificar a continuidade do acesso legítimo. O controle do SOAR também permanece acessível. O prazo é 45 s, com reversão antecipada. A expiração que libera a sessão é uma conveniência de demonstração. Um sistema de produção precisa de uma política própria de revogação e recuperação de sessões.

Severidade alta e sequência completa permitem solicitar aprovação somente quando a política admite contenção. A autorização vinculada ao contexto ou uma exportação já negada levam a acompanhamento, inclusive se o analista selecionar alta manualmente. O caso de alteração de permissões reproduz logs de IAM. A reversão do bloqueio demonstra restauração de acesso ao serviço. Reverter uma permissão real exige outro conector e procedimento operacional.

Cada decisão guarda ator fictício `analista-demo`, ação, horário, evidências e ID de aprovação. A triagem registra provedor, modelo, digest, prompt e resultado validado. O Decision Receipt reúne essas informações em JSON exportável. O laboratório demonstra rastreabilidade. A identificação do operador usa um personagem fixo do exercício.

MTTR é a média do intervalo entre a identificação do incidente e a aplicação da contenção, incluindo a espera de aprovação. Só entram rodadas com contenção aplicada, separadas entre manual e assistida. Detecção, triagem e aprovação também aparecem separadamente. A taxa de automação mede triagens assistidas válidas entre rodadas assistidas que chegaram à triagem. A aprovação continua humana.

O botão **Avaliar detector** executa oito casos controlados da clínica, incluindo os três incidentes, o plantão autorizado, login comum, telemetria ausente, sessões diferentes e atividade fora da janela. O painel informa VP, VN, FP, FN, FPR e FNR. O resultado mede o detector antes da revisão contextual. Essa amostra pequena permite reproduzir comportamentos e limites, e a precisão em produção requer uma avaliação específica.

## Recursos para investigação

O replay e a história apresentam os eventos e seus vínculos com os logs. O Challenger procura explicações alternativas. O detector de lacunas sugere evidências ausentes. O Shadow Mode prevê o impacto antes da aprovação. A memória usa conclusões revisadas no navegador. O Incident DNA compara sequência, técnicas e ativos. O perfil comportamental compara logins anteriores da conta. O SOC Pulse acompanha casos locais e incidentes abertos da sessão. A Arena treina classificação e escolha de evidência.

O Ask Your SOC responde a consultas estruturadas sobre prontuários, exportações, permissões, falhas por IP e severidade. Ele consulta a base e cita exemplos. As perguntas são interpretadas por regras locais. A triagem e a segunda revisão são os pontos de integração com o LLM.

## Reproduzir a base

```powershell
node lab/generate-clinic.cjs
node lab/generate-clinic.cjs logs/clinica-investigacao-205k.jsonl
```

O catálogo único dos cenários fica em `lab/clinic.json`, compartilhado entre o painel, o gerador e o aplicativo das VMs. Os registros do cenário anterior de SSH continuam disponíveis para comparação histórica.

## Validação realizada

A base foi descompactada e conferida com 205.000 linhas JSON válidas, indicação sintética em todos os registros e 80 consultas individuais no cenário principal. Os fluxos foram exercitados pelo painel em convidados Linux no navegador e no VirtualBox instalado. Foram verificados os três incidentes, o controle benigno, a seleção manual de evidências, as severidades, a falha de triagem, o bloqueio após aprovação, a sessão legítima da mesma origem, a reversão, a auditoria, o chat estruturado e o gabarito da Arena. A suíte Go também foi executada nos convidados Linux.

Os indicadores de escala, dispositivo conhecido e autorização são fixtures do catálogo. O horário UTC da rodada ao vivo corresponde à execução, e o contexto de plantão é o contexto fictício definido para o exercício. Integrações com escala de pessoal, diretório corporativo e prontuário operacional precisam fornecer esses sinais em uma implantação real.

Em 13 de novembro de 2026, o modo Ollama foi validado no VirtualBox deste computador com Qwen2.5 1.5B Q4_K_M e Ollama 0.40.16, em CPU. O cenário principal e o plantão autorizado produziram JSON aceito e uma segunda revisão local validada. Foram verificados prioridade alta para a sequência suspeita, prioridade baixa para o controle autorizado, aprovação humana, suspensão da sessão suspeita, acesso da sessão legítima e reversão. Uma seleção manual que omitiu o registro de mudança manteve a autorização indicada no próprio evento de exportação. Os registros finais estão no JSONL de demonstração. As rodadas históricas com provedor Ollama reproduzem inferências já executadas localmente. O site público continua oferecendo triagem simulada para novas rodadas.
