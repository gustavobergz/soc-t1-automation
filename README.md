# Autonomous SOC Tier 1

Laboratório de SOC para investigar abuso de credenciais, correlacionar evidências e demonstrar contenção com aprovação humana. Os eventos, o enriquecimento e a triagem assistida são simulados. A contenção é aplicada somente ao serviço HTTP de demonstração.

## Abrir em um clique

[**Abrir a demonstração no navegador**](https://gustavobergz.github.io/soc-t1-automation/)

- **Visão geral** reúne os indicadores da base carregada, os incidentes da demonstração e a topologia da rede isolada. Use **Ctrl+K** para buscar em qualquer área.
- **Investigar logs** abre o explorador com 205.000 eventos sintéticos. Filtre pelo IP `198.51.100.27` para encontrar oito falhas de autenticação, um login aceito e uma consulta de privilégios. Abra o JSON original, selecione as evidências e exporte o caso.
- **Operação ao vivo** inicia quatro VMs Linux isoladas no navegador. A rodada manual permite escolher as evidências, a severidade e a justificativa. A rodada assistida demonstra a correlação, a aprovação humana, o bloqueio por 45 segundos e a opção de desbloquear.

## Rodar localmente

1. Baixe o projeto pelo botão **Code → Download ZIP** e extraia toda a pasta.
2. Abra **index.html** no Chrome ou Edge. Para usar o explorador, escolha `logs/soc-investigacao-205k.jsonl.gz` em **Carregar base de exemplo**.
3. Para usar o **VirtualBox no Windows**, tenha VirtualBox e Node.js instalados e abra **INICIAR VIRTUALBOX.cmd**. O iniciador registra as quatro VMs da demo e abre o painel local.

O [roteiro de oito minutos](LEIA-ME.md) inclui a topologia, o fluxo de aprovação e exemplos de investigação. O [log de validação](logs/soc-demo.jsonl) registra execuções anteriores. Os [componentes de terceiros](THIRD_PARTY_NOTICES.md) estão descritos separadamente.

## Base sintética

O arquivo `logs/soc-investigacao-205k.jsonl.gz` contém 205.000 objetos JSON, um por linha. O explorador lê o gzip diretamente. Para gerar uma cópia sem compressão, use `node lab/generate-logs.cjs`. Para reproduzir a versão compactada, use `node lab/generate-logs.cjs logs/soc-investigacao-205k.jsonl.gz`.
