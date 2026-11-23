# Autonomous SOC Tier 1

Protótipo acadêmico de triagem de incidentes com **205.000 eventos fictícios**, revisão humana, Ollama local e relatório TXT para encaminhamento ao T2. Versão 2.1.0.

## Rodar localmente

Requer Node.js 22 ou superior. Baixe ou clone este repositório inteiro. Não há dependências npm para instalar.

```sh
node servidor-local.cjs
```

Abra http://127.0.0.1:8893/. No Windows, também pode executar `ABRIR_LOCAL.cmd`. O servidor só escuta em 127.0.0.1. Use esse endereço para o conector local e a gravação de sessões.

Para uma demonstração sem servidor, abra `index.html` no navegador. A base completa está embutida. A [versão web](https://gustavobergz.github.io/soc-t1-automation/) também permite a demonstração e o download do relatório; para o Ollama, prefira o servidor local.

## Fluxo do analista

1. A base embutida é lida integralmente pelas regras; quatro incidentes aparecem na fila. `Carregar outro log` aceita TXT, LOG, JSONL e GZ compatíveis com os eventos reconhecidos.
2. Revise fatos, contexto e linhas originais. A severidade pode ser alterada com justificativa; a revisão humana guiada registra o tempo até a classificação.
3. Selecione `Manual · sem IA`, `Simulada (fixture)` ou `Ollama local`. A IA recebe resumos e evidências-chave, não todas as 205.000 linhas brutas. A resposta é validada antes de ser apresentada.
4. `Aprovar atividade` registra atividade considerada legítima. `Registrar acompanhamento` mantém investigação sem nova contenção. `Bloquear` autoriza uma ação simulada; pode ser revertida ou expirar pelo prazo. Não existe veto fixo baseado na sugestão da IA, autorização ou exportação recusada.
5. Clique em **Relatório T2**, revise o texto, use **Visualizar**, **Salvar rascunho** e **Baixar TXT**. O resumo reúne severidades, justificativas, recomendações da IA, decisões e referências de evidência. Os rascunhos são preservados no navegador. `Atualizar dados` gera outra versão, e a anterior pode ser restaurada.
6. Encaminhe manualmente o TXT, o log original e o JSON da auditoria ao T2. O aplicativo não envia mensagens ao time. Editar o TXT não muda as evidências nem as decisões de origem.

Com o servidor local, os arquivos são gravados em `sessoes/`. Para abrir o relatório de um registro salvo, use `/?provider=manual&report_session=UUID-DA-SESSAO`. Isso abre o resumo desse registro sem restaurar a fila ou executar novamente a IA. O relatório identifica sua sessão de origem. As sessões e rascunhos individuais não fazem parte deste repositório.

## Ollama local

Execute o Ollama na porta 11434 e instale o modelo que deseja usar. O padrão do aplicativo é `qwen2.5:1.5b`. Confira a conexão e o modelo em `Ajustes`, selecione `Ollama local` e clique em `Analisar todos com IA`. O servidor encaminha as chamadas ao Ollama na mesma máquina. O tempo exibido inclui a chamada e a validação da resposta, não somente a inferência interna do modelo.

## Fonte e verificações

- `motor.js`: parser, correlação, fatos e resposta simulada.
- `interface.js`: interface, revisão humana, integração com IA e decisões.
- `relatorio.js`: geração do TXT para o T2.
- `index.html`: layout e aplicação autossuficiente com fontes e base embutidos.
- `servidor-local.cjs`: servidor, conector do Ollama e arquivos de sessão.
- `clinica-205mil.txt` e `clinica-investigacao-205k.jsonl.gz`: base completa, em texto e gzip.
- `tests/`: verificações da resposta manual e do relatório.

Após editar os arquivos JS, execute:

```sh
npm run build
npm run check
npm test
```

Os comandos utilizam apenas o Node.js e os arquivos deste repositório. Os testes técnicos são identificados como validação e não constituem resultados de participantes.

## Resultados e limites

O [slide final e sua descrição](docs/resultados/LEIA-ME.md) mantêm o layout anterior, com faixas informadas: manual de 60 a 90 s por caso e Ollama de 20 a 30 s por caso. Essas faixas não substituem os tempos medidos na avaliação guiada. Concordância de severidade e JSON válido não demonstram acurácia ou ganho de produtividade.

Todas as ações são simuladas; não há integração de bloqueio real com contas, firewall, endpoint ou SIEM. Os dados clínicos são fictícios. O projeto demonstra interpretação de logs, correlação, triagem assistida e decisão humana.

Consulte `COMO_RODAR_E_EDITAR.txt` para o guia atual. Os manuais e imagens anteriores preservados em `docs/`, `DOCUMENTACAO_REPOSITORIO.md` e `DOCUMENTACAO_SIMULACAO.md` descrevem versões anteriores; capturas e regras antigas podem diferir desta interface.
