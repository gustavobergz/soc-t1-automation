# SOC Clínica · Autonomous SOC Tier 1

Aplicação demonstrativa de um fluxo SOC Tier 1 para investigação e resposta a alertas em uma clínica. A interface reúne eventos, evidências, triagem, aprovação humana e registro de casos. Contas, pacientes e eventos são dados mockados, criados para apresentar como o fluxo funcionaria em operação.

[**Abrir a demonstração**](https://gustavobergz.github.io/soc-t1-automation/)

## Começar

- **Análise de incidentes** reúne atendimentos registrados, histórico, evidências, revisão e comprovantes em JSON.
- **Investigar logs** carrega uma base de demonstração com 205.000 eventos. Busque `MED-017`, `REC-004` ou `ENF-009`, selecione evidências individuais e salve um caso.
- **Atendimento de alertas** processa o fluxo selecionado no ambiente local. Compare triagem manual, resposta de referência e Ollama local.
- **Treinamento** apresenta fluxos de demonstração com classificação e escolha da evidência decisiva.
- **Qualidade e auditoria** apresenta a política, as métricas e a avaliação controlada do detector.

A interface usa dados de demonstração. No site, a triagem assistida apresenta uma resposta de referência identificada; no modo local, a aplicação pode consultar o Ollama pelo iniciador VirtualBox.

## Windows com IA local

1. Baixe o ZIP do repositório e extraia toda a pasta. Tenha VirtualBox e Node.js instalados.
2. Execute **CONFIGURAR IA LOCAL.cmd**. Ele prepara o Ollama 0.40.16 para CPU, verifica o SHA256 do pacote utilizado e baixa o modelo local `qwen2.5:1.5b`.
3. Execute **INICIAR COM IA LOCAL.cmd**.
4. No painel, selecione um cenário e **Assistida · Ollama local**.

A configuração inicial usa internet. O instalador baixa cerca de 46 MB de componentes CPU da distribuição oficial, utiliza um ZIP temporário de aproximadamente 1,6 GB e baixa cerca de 986 MB de pesos do modelo. Reserve pelo menos 3 GB de espaço livre para essa preparação. Os downloads concluídos ficam disponíveis para reutilização.

O servidor de inferência iniciado pelo projeto usa `127.0.0.1:11434` com recursos de nuvem desativados. O conector envia contagens, indicadores e IDs de evidência. Os arquivos do serviço e os pesos ficam em `%LOCALAPPDATA%\SOC-Tier1`. A entrada e a saída validadas podem ser inspecionadas na triagem em JSON. [Documentação do Ollama](https://docs.ollama.com/faq)

Para executar o ambiente local com os dados de demonstração, abra **INICIAR VIRTUALBOX.cmd**. O site também executa os serviços isolados pelo v86 no navegador. O laboratório SSH anterior continua selecionável. Para encerrar as VMs criadas pelo projeto, execute `powershell -File .\VirtualBox.ps1 -Mode Stop`.

## Documentação e demonstração

O [manual do repositório e das páginas](DOCUMENTACAO_REPOSITORIO.md) explica as sete telas, as tecnologias utilizadas, a organização do código e como executar o laboratório. Inclui capturas do sistema e exemplos de investigação. [Baixar o manual em Word](docs/Manual_SOC_Clinica.docx).

A [documentação técnica](DOCUMENTACAO_SIMULACAO.md) explica os fluxos de demonstração, o fluxo de dados, as regras, os campos de logs, a IA local, os controles de privacidade, as métricas e um roteiro de apresentação de oito minutos. O [guia rápido](LEIA-ME.md) resume a apresentação.

A contenção suspende uma sessão de teste no serviço HTTP por 45 s, após aprovação. O painel verifica que a sessão legítima da mesma origem continua acessível e permite reversão antecipada. A autenticação, o prontuário e o IAM são reproduções sintéticas. O coletor e o playbook em Go representam os papéis de Wazuh e n8n. A integração com os produtos originais e dados operacionais exige uma etapa própria.

A memória é uma comparação entre casos revisados no navegador. O chat executa consultas estruturadas locais. A triagem e a revisão opcional são as integrações com o LLM. A execução local faz parte dos controles de proteção de dados descritos no documento, e a conformidade de uma implantação real precisa ser avaliada no seu contexto.

A prioridade operacional vem das regras clínicas. O painel apresenta separadamente a severidade sugerida pela IA e destaca divergências. As explicações do modelo são consultivas e devem ser conferidas com os fatos registrados. O comprovante mantém a classificação da regra e a proposta original do modelo.

## Reproduzir os eventos

```powershell
node lab/generate-clinic.cjs
```

O gerador produz `logs/clinica-investigacao-205k.jsonl.gz`. Para uma cópia sem compressão, use `node lab/generate-clinic.cjs logs/clinica-investigacao-205k.jsonl`. O catálogo compartilhado dos cenários fica em `lab/clinic.json`. A base e os logs anteriores de SSH continuam no repositório.

[Componentes e licenças de terceiros](THIRD_PARTY_NOTICES.md)
