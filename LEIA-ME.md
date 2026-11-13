# Roteiro rápido — SOC Clínica

O laboratório demonstra como um SOC investiga acesso e operações suspeitas em uma clínica fictícia com apoio de triagem local e aprovação humana.

## Preparação

Abra a [demonstração](https://gustavobergz.github.io/soc-t1-automation/) ou o iniciador VirtualBox. Para usar o modelo real, execute primeiro **CONFIGURAR IA LOCAL.cmd** e depois **INICIAR COM IA LOCAL.cmd**. Prepare o modelo antes da apresentação.

## Oito minutos

1. Apresente a clínica e informe que todos os dados são fictícios.
2. Em **Operação ao vivo**, escolha **Conta médica roubada** e execute a rodada assistida.
3. Abra o login, as 80 consultas resumidas e o pedido de exportação. Explique a diferença entre suspeita e confirmação.
4. Em **Revisar incidente**, mostre a linha do tempo, as contraprovas e as lacunas. Abra o JSON para conferir o que chegou ao modelo.
5. Simule o impacto e aprove a contenção. Mostre HTTP 403 para a sessão suspeita e HTTP 204 para a sessão legítima. Reverta e confira a liberação.
6. Execute **Exportação indevida** e mostre a recusa da aplicação e a severidade média. A operação negada segue para investigação.
7. Compare **Alteração suspeita de permissões** com **Plantão autorizado**. No controle benigno, a autorização deve direcionar o caso para acompanhamento.
8. Abra o comprovante e explique as métricas observadas. Os resultados medem o experimento controlado.

Use **Análise de incidentes** para reproduzir rodadas registradas. No explorador, busque MED-017, REC-004 e ENF-009 para reunir registros individuais da base de 205 mil eventos.

A [documentação completa](DOCUMENTACAO_SIMULACAO.md) descreve arquitetura, regras, logs, IA local, privacidade, resposta e limites da simulação.
