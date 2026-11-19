# SOC Clínica com IA local

Em **Método e auditoria**, clique **Conferir números do TCC** para recalcular o acervo original. As novas rodadas ficam separadas desse histórico. Para executar com Ollama local e registro em arquivo, use `INICIAR COM IA LOCAL.cmd` e acesse `http://127.0.0.1:8771/`.

Laboratório acadêmico de SOC para investigar atividades suspeitas em uma clínica fictícia. A simulação cobre conta médica roubada, exportação indevida, alteração de permissões e um plantão autorizado de comparação. Os dados são inteiramente fictícios. O analista revisa as evidências e decide sobre a contenção.

[**Abrir a demonstração**](https://gustavobergz.github.io/soc-t1-automation/)

## Começar

- **Análise de incidentes** abre rodadas registradas, replay, história, contraprovas, lacunas e comprovante em JSON.
- **Investigar logs** carrega 205.000 eventos da clínica. Busque `MED-017`, `REC-004` ou `ENF-009`, selecione evidências individuais e salve um caso.
- **Operação ao vivo** executa o cenário escolhido nas quatro VMs. Compare triagem manual, resposta simulada e Ollama local.
- **SOC Arena** apresenta os quatro cenários com classificação e escolha da evidência decisiva.
- **Método e auditoria** apresenta a política, as métricas e a avaliação controlada do detector.

O site público usa uma triagem simulada identificada. O modo com modelo real usa Ollama no computador pelo iniciador VirtualBox.

## Windows com IA local

1. Baixe o ZIP do repositório e extraia toda a pasta. Tenha VirtualBox e Node.js instalados.
2. Execute **CONFIGURAR IA LOCAL.cmd**. Ele prepara o Ollama 0.40.16 para CPU, verifica o SHA256 do pacote utilizado e baixa o modelo local `qwen2.5:1.5b`.
3. Execute **INICIAR COM IA LOCAL.cmd**.
4. No painel, selecione um cenário e **Assistida · Ollama local**.

A configuração inicial usa internet. O instalador baixa cerca de 46 MB de componentes CPU da distribuição oficial, utiliza um ZIP temporário de aproximadamente 1,6 GB e baixa cerca de 986 MB de pesos do modelo. Reserve pelo menos 3 GB de espaço livre para essa preparação. Os downloads concluídos ficam disponíveis para reutilização.

O servidor de inferência iniciado pelo projeto usa `127.0.0.1:11434` com recursos de nuvem desativados. O conector envia contagens, indicadores e IDs de evidência. Os arquivos do serviço e os pesos ficam em `%LOCALAPPDATA%\SOC-Tier1`. A entrada e a saída validadas podem ser inspecionadas na triagem em JSON. [Documentação do Ollama](https://docs.ollama.com/faq)

Para executar com triagem simulada, abra **INICIAR VIRTUALBOX.cmd**. O site também executa as VMs pelo v86 no navegador. O laboratório SSH anterior continua selecionável. Para encerrar as VMs criadas pelo projeto, execute `powershell -File .\VirtualBox.ps1 -Mode Stop`.

## Documentação e demonstração

O [manual do repositório e das páginas](DOCUMENTACAO_REPOSITORIO.md) explica as sete telas, as tecnologias utilizadas, a organização do código e como executar o laboratório. Inclui capturas do sistema e exemplos de investigação. [Baixar o manual em Word](docs/Manual_SOC_Clinica.docx).

A [documentação da simulação](DOCUMENTACAO_SIMULACAO.md) explica os cenários, o fluxo de dados, as regras, os campos de logs, a IA local, os controles de privacidade, as métricas e um roteiro de apresentação de oito minutos. O [guia rápido](LEIA-ME.md) resume a apresentação.

A contenção suspende uma sessão de teste no serviço HTTP por 45 s, após aprovação. O painel verifica que a sessão legítima da mesma origem continua acessível e permite reversão antecipada. A autenticação, o prontuário e o IAM são reproduções sintéticas. O coletor e o playbook em Go representam os papéis de Wazuh e n8n. A integração com os produtos originais e dados operacionais exige uma etapa própria.

A memória é uma comparação entre casos revisados no navegador. O chat executa consultas estruturadas locais. A triagem e a revisão opcional são as integrações com o LLM. A execução local faz parte dos controles de proteção de dados descritos no documento, e a conformidade de uma implantação real precisa ser avaliada no seu contexto.

A prioridade operacional vem das regras clínicas. O painel apresenta separadamente a severidade sugerida pela IA e destaca divergências. As explicações do modelo são consultivas e devem ser conferidas com os fatos registrados. O comprovante mantém a classificação da regra e a proposta original do modelo.

## Reproduzir os eventos

```powershell
node lab/generate-clinic.cjs
```

O gerador produz `logs/clinica-investigacao-205k.jsonl.gz`. Para uma cópia sem compressão, use `node lab/generate-clinic.cjs logs/clinica-investigacao-205k.jsonl`. O catálogo compartilhado dos cenários fica em `lab/clinic.json`. A base e os logs anteriores de SSH continuam no repositório.

[Componentes e licenças de terceiros](THIRD_PARTY_NOTICES.md)

## Métricas e registros das execuções

As métricas distinguem manual, assistida simulada e assistida Ollama. O MTTR inclui somente contenções verificadas: aprovação vinculada, sessão suspeita com HTTP 403 e sessões legítima e de controle com HTTP 204. Ausência de contenção permanece sem valor. Os grupos da demonstração não comprovam ganho de produtividade humana.

O painel histórico confere o SHA256 de `logs/clinica-demo.jsonl` e recalcula as 12 rodadas originais, preservando suas amostras e valores. As execuções novas não alteram esse arquivo.

No iniciador VirtualBox, a disponibilidade da IA é consultada no serviço Ollama antes de habilitar a triagem real. O diário de cada sessão fica em `logs/novas-execucoes/sessao-<id>.jsonl`, com sequência, versões e encadeamento de hashes. Essa pasta é local e não entra no Git. O encadeamento permite conferir consistência, mas não substitui autenticação individual ou auditoria imutável. A opção **Exportar JSONL** continua disponível no painel.

O campo **Tipo de execução** distingue demonstrações de testes técnicos automatizados. Esses registros não constituem um estudo comparativo com participantes humanos.
