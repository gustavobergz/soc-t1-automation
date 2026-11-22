# Roteiro rápido — SOC Clínica

A apresentação demonstra um protótipo de SOC Tier 1 com dados de clínica fictícios. A interface organiza eventos, evidências, triagem e aprovação humana para mostrar como esse fluxo funcionaria.

## Antes de apresentar

1. Baixe e extraia a branch atualizada do projeto.
2. Confirme que VirtualBox e Node.js estão instalados.
3. Abra **INICIAR VIRTUALBOX.cmd** e aguarde os quatro serviços ficarem disponíveis.
4. No navegador, confirme que o painel abriu em `http://127.0.0.1:8771/`.
5. Faça um ensaio completo com **Conta médica roubada** e o controle benigno.
6. Para a triagem padrão, use **Triagem assistida**: ela mostra uma resposta de referência. Só escolha **Triagem com modelo local** se o Ollama já estiver configurado e testado.
7. Deixe um vídeo curto ou capturas da interface prontos como plano B.

## Demonstração do Gustavo — 8 minutos

**0:00–1:00 — Visão geral**  
Mostre os indicadores e a arquitetura operacional. Explique que a clínica, as contas e os eventos são dados de demonstração e que a rede de execução é isolada.

**1:00–2:00 — Investigar logs**  
Abra **Investigar logs**, busque `MED-017` e marque um ou dois registros como evidência. Destaque os identificadores que conectam eventos e investigação. A base de 205 mil registros é usada para investigação; não são 205 mil testes do detector.

**2:00–4:00 — Atender o alerta**  
Abra **Atendimento de alertas**, selecione **Conta médica roubada** e execute **Triagem assistida**. Mostre o login em dispositivo desconhecido e fora da escala, as 80 consultas sem vínculo de atendimento e a solicitação de exportação. Diga que a solicitação, sozinha, não comprova download ou vazamento.

**4:00–5:30 — Revisar a triagem**  
Mostre os fatos registrados, a prioridade atribuída pela regra e a recomendação da triagem. Na modalidade padrão, identifique a triagem como resposta de referência com dados mockados. Se usar Ollama, diga que o modelo está sendo executado localmente.

**5:30–7:00 — Aprovar e verificar a resposta**  
Mostre a aprovação humana e a contenção da sessão de demonstração. Ela dura até 45 segundos e pode ser revertida antes. Confira o bloqueio da sessão suspeita e que a sessão legítima de controle continua acessível; depois faça a reversão.

**7:00–8:00 — Comparar com atividade autorizada**  
Selecione **Controle benigno · plantão autorizado** e explique como autorização e contexto mudam a decisão. Encerre passando a palavra para o próximo integrante.

## Para responder com precisão

- Apresente o sistema como um protótipo demonstrativo com dados mockados.
- Wazuh e n8n são referências arquiteturais; não foram integrados como produtos completos.
- A solicitação de exportação do primeiro cenário não prova que dados foram extraídos.
- A IA auxilia a triagem; regras e aprovação humana controlam a contenção.
- Não prometa redução de tempo, custo ou MTTR: o TCC não demonstra esses resultados.
- Se a execução ao vivo falhar, use o vídeo ou as capturas e continue explicando o fluxo.
