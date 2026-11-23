# Texto-base para atualizar o TCC

## Título

Autonomous SOC Tier-1: apoio à triagem de incidentes de segurança em uma clínica fictícia

## Resumo

Este trabalho apresenta um protótipo de apoio à triagem inicial de incidentes em uma clínica fictícia. O fluxo reúne eventos de autenticação, acesso a prontuários, solicitações de exportação, agenda, farmácia e permissões administrativas. A aplicação disponibiliza uma base de 205.000 eventos sintéticos, gerada a partir de padrões estruturais de logs de infraestrutura e adaptada para serviços e papéis clínicos fictícios. Os registros não contêm nomes, diagnósticos ou conteúdo real de prontuários. A correlação organiza os eventos por conta, sessão e janela temporal; a IA local produz uma classificação inicial e uma justificativa estruturada. O analista examina as evidências, pode corrigir a classificação e decide se aceita ou rejeita a recomendação. A contenção de teste depende de política e aprovação humana. O protótipo demonstra o fluxo e a investigação em dados simulados, mas não comprova desempenho em uma clínica real. A rapidez relativa entre analista e modelo deve ser apresentada apenas após medições pareadas no mesmo cenário e ambiente.

**Palavras-chave:** SOC Tier-1; clínica fictícia; SIEM; triagem de incidentes; inteligência artificial; revisão humana.

## Objetivo geral

Desenvolver e avaliar um protótipo de apoio a um SOC Tier-1 que correlaciona eventos de uma clínica fictícia, apresenta uma classificação inicial por IA local e permite que o analista revise as evidências, corrija a análise e aprove ou rejeite a resposta proposta.

## Escopo e cenário

O cenário principal acompanha o uso suspeito de uma conta médica fictícia. A sequência inclui falhas de autenticação, login bem-sucedido em dispositivo desconhecido e fora da escala, consultas a referências fictícias de prontuário sem vínculo de atendimento e uma solicitação de exportação. A solicitação registrada não demonstra que os dados saíram do sistema. Um plantão autorizado, uma exportação bloqueada e uma alteração de permissões complementam os casos para avaliar contexto legítimo, recusa de ação e revisão de privilégios.

A aplicação trabalha somente com metadados fictícios. As referências de pacientes e atendimentos usam identificadores como PAC-FICT e ATD-FICT; o conteúdo de consultas, exames e diagnósticos não é armazenado.

## Base de eventos

A base de investigação contém 205.000 eventos sintéticos em linhas de texto. Cada registro segue o formato do arquivo de referência: timestamp ISO seguido por pares `chave="valor"`, como `host`, `service`, `user`, `src`, `action`, `status` e, quando aplicável, `alert`. O aplicativo lê essas linhas diretamente, preserva a linha original para revisão e normaliza em memória os campos usados para busca e métricas; o arquivo de origem não precisa ser convertido em JSON. A versão para o protótipo representa infraestrutura de uma clínica fictícia, com serviços de autenticação, prontuário, agenda, farmácia, gateway, DNS, compartilhamento de arquivos e banco de dados.

Os registros contêm somente metadados simulados: horário, serviço, host, usuário fictício, endereço de origem, ação ou consulta, resultado, volume de linhas ou bytes e identificadores fictícios de pacientes. Indicadores como `port_scan`, `bulk_access`, `mass_select`, `dns_tunneling` e `data_exfiltration` são sinais do cenário sintético; não comprovam atividade real nem saída de dados. O conteúdo de consultas, exames e diagnósticos não é armazenado. A base foi produzida para representar atividade de rotina e sequências controladas; a contagem de 205.000 refere-se aos eventos do corpus, não ao número de incidentes.
## Fluxo de triagem

1. O coletor normaliza e correlaciona os eventos por conta, sessão, serviço e janela temporal.
2. O sistema apresenta a sequência de evidências e a regra que abriu o caso.
3. A IA local sugere prioridade, resumo, incerteza e próximos passos em formato estruturado.
4. O analista confere os registros, pode corrigir a classificação e registra sua justificativa.
5. A política verifica se uma ação é elegível; a contenção de teste só ocorre após aprovação humana.
6. O painel registra decisão, aprovação, resultado e possibilidade de reversão.

A IA fornece a análise inicial; ela não decide sozinha pela contenção. A validação de formato JSON não é prova de que a interpretação esteja correta.

## Avaliação e apresentação de resultados

O corpus de 205.000 eventos permite demonstrar busca, filtragem, seleção de evidências e construção de casos. A contagem do corpus não mede precisão nem rapidez. Para comparar a decisão inicial manual e a do Ollama, cada par deve usar o mesmo cenário, configuração e equipamento. O relógio começa no primeiro evento de telemetria e termina quando a classificação inicial é registrada. A comparação deve excluir a triagem simulada e informar todas as repetições, além de conferir se as classificações estão corretas.

Até a execução desse protocolo, não se deve afirmar que a IA é mais rápida que o analista. O tempo de resposta ou MTTR, medido até a contenção, é uma medida diferente do tempo até a classificação inicial. Resultados de uma única rodada ou amostras sem pareamento devem ser descritos como observações, sem generalização.

## Limitações

A clínica, os usuários, os eventos e as referências de prontuário são fictícios. A base não representa tráfego real nem mede a operação de um serviço de saúde. O protótipo não está integrado a prontuários, escalas, identidade ou resposta de uma clínica real. Resultados dependem da regra, do modelo local, da máquina, do cenário e da atuação do analista. A continuidade do atendimento é um objetivo de projeto; não há resultado clínico ou redução operacional medida.
