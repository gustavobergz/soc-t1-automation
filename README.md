# Autonomous SOC Tier 1

Aplicação web demonstrativa para triagem de alertas de um SOC N1 usando registros fictícios de uma clínica.

## Abrir

Acesse o [aplicativo publicado](https://gustavobergz.github.io/soc-t1-automation/) ou abra `index.html` localmente no navegador.

## Fluxo demonstrado

1. Carregue logs de texto com data/hora e campos no formato `chave=valor`.
2. A aplicação interpreta os registros e correlaciona sinais para destacar incidentes.
3. A triagem pode usar respostas simuladas (modo padrão) ou o Ollama local, quando configurado.
4. O analista revisa evidências, decide se aprova ou rejeita a ação sugerida e consulta a auditoria.

O aplicativo não executa bloqueios reais em firewall, endpoints, contas ou SIEM. As ações de resposta são demonstrativas e ficam registradas na interface.

## Dados

Os registros e cenários são fictícios. O repositório mantém um exemplo de log em texto em `logs/clinica-exemplo.txt`. Para usar outra base, selecione o arquivo `.txt` ou `.log` no próprio aplicativo. A leitura do arquivo não garante que todas as regras reconhecerão seus campos; isso depende do formato e dos eventos presentes.

## Modo de IA

O modo **Simulada (fixture)** é o padrão e serve para uma demonstração previsível. **Ollama local** envia a triagem para o serviço Ollama configurado no computador. A recomendação da IA é revisada pelo analista e não controla a política de resposta.

Este projeto é um protótipo acadêmico para demonstrar análise de logs, correlação, triagem assistida e decisão humana.
