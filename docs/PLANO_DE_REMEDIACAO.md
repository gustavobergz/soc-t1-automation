# Plano de remediação do protótipo SOC Tier 1

Este plano converte as limitações registradas no TCC e na documentação em etapas de evolução verificáveis. O código atual continua sendo uma prova de conceito acadêmica: as ações abaixo não autorizam uso em produção.

## 1. Aumentar a cobertura de detecção sem ampliar contenção automática

**Problema observado:** a suíte atual contém 8 casos sintéticos: 3 VP, 1 FP, 1 VN e 3 FN. A sensibilidade observada é 50%; os FN correspondem à ausência de login, separação de sessões e eventos além da janela de 120 segundos.

**Trabalho:**
- Separar “sinal para investigação” de “cadeia completa elegível para contenção”.
- Criar regras de evidência parcial para que ausência de um elo não descarte silenciosamente atividade relevante.
- Nunca permitir contenção apenas por uma regra parcial; exigir correlação completa, política elegível e aprovação.
- Expandir a suíte com variantes independentes de sequência, relógio, sessão e telemetria ausente. Manter um conjunto de validação separado dos casos usados para ajustar regras.
- Registrar, por caso, evidências, resultado esperado, severidade, decisão permitida e motivo.

**Critério de aceite:** o benchmark informa VP, FP, VN, FN, sensibilidade, precisão e taxa de falsos positivos em treino e validação separados. Todos os casos incompletos permanecem sem contenção automática. Mudanças de limiar exigem justificativa e comparação contra a versão anterior.

## 2. Vincular aprovação a uma identidade e proteger a trilha

**Problema observado:** o ator é o identificador fixo `analista-demo`; registros e casos são locais e não formam uma auditoria imutável.

**Trabalho:**
- Definir provedor de identidade e papéis antes de escolher uma implementação de autenticação.
- Vincular cada aprovação ou rejeição à identidade autenticada, incidente, evidências revisadas, horário e justificativa.
- Registrar eventos de auditoria em armazenamento append-only ou com encadeamento criptográfico e verificação explícita.
- Tirar o estado autoritativo de casos e decisões do `localStorage`; mantê-lo apenas para preferências e rascunhos.
- Documentar retenção, recuperação, permissões de leitura e tratamento de falha do armazenamento.

**Critério de aceite:** uma aprovação não pode ser enviada em nome de outro analista; toda decisão pode ser validada depois da reinicialização; uma alteração ou remoção da trilha é detectável.

## 3. Integrar fontes reais somente em ambiente de teste

**Problema observado:** o coletor e o playbook em Go representam papéis de SIEM/SOAR. Wazuh, n8n, IAM e APIs externas não estão integrados.

**Trabalho:**
- Escolher as plataformas e versões disponíveis no laboratório antes de desenvolver conectores.
- Implementar adaptadores isolados para ingestão, normalização e encaminhamento; manter o formato interno independente do fornecedor.
- Iniciar com leitura e modo dry-run. Não enviar ações de contenção a serviços reais durante a validação inicial.
- Testar campos ausentes, duplicação, atraso, relógios divergentes, falhas de API e limites de taxa.
- Guardar configuração sensível fora do repositório e reduzir permissões dos tokens ao mínimo necessário.

**Critério de aceite:** dados de teste percorrem a integração ponta a ponta, com IDs e timestamps preservados; falhas do conector não geram contenção; cada fornecedor e versão usados ficam registrados.

## 4. Avaliar a IA com um protocolo comparável

**Problema observado:** existem duas chamadas locais avaliadas; as justificativas foram genéricas e a latência foi de 35,452 s e 47,128 s. Não houve comparação pareada com analistas.

**Trabalho:**
- Comparar triagem determinística, triagem com fixture e triagem com modelo local usando as mesmas evidências e regras de aprovação.
- Repetir cada caso e registrar modelo, digest, prompt, parâmetros, hardware, tempo monotônico e resultado validado.
- Avaliar separadamente formato JSON, acerto de classificação, uso de evidências, explicação, incerteza e recomendações.
- Se houver participantes, obter autorização apropriada e usar ordem contrabalanceada e revisão cega das justificativas.
- Não usar latência de fixture como substituta para inferência real, nem misturar os tempos em uma média única.

**Critério de aceite:** resultados são reproduzíveis e cada métrica identifica sua unidade, amostra, modalidade e limitações. A afirmação de ganho de produtividade só pode ser feita após comparação humana equivalente.

## 5. Melhorar rastreabilidade temporal e reprodução

**Problema observado:** o TCC registra diferenças entre relógios das VMs e falta de versões completas por execução.

**Trabalho:**
- Registrar em cada rodada o SHA do código, versão das regras, modelo/prompt, configuração e hashes dos arquivos de entrada.
- Medir durações com relógio monotônico; manter UTC para correlação entre sistemas.
- Registrar estado de sincronização, origem do relógio e desvio observado em cada VM.
- Empacotar comandos, dados sintéticos e saídas necessárias para reproduzir benchmark e resultados.

**Critério de aceite:** uma rodada pode ser associada à versão exata do código, regras e dados; os tempos de duração não dependem de ajuste de relógio do sistema; os artefatos reproduzem as métricas documentadas.

## Sequência recomendada

1. Estabelecer o benchmark ampliado e separar alerta parcial de contenção.
2. Escolher provedor de identidade e armazenamento de auditoria.
3. Fazer conectores de leitura em ambiente de teste.
4. Executar a avaliação comparável da IA e dos fluxos.
5. Revisar os documentos acadêmicos para distinguir resultados demonstrados de trabalho futuro.

## Dependências ainda não definidas

A implementação das etapas 2 e 3 requer escolher provedor de identidade, destino de auditoria, SIEM/SOAR e ambiente de teste. A etapa 4 requer definir acesso ao hardware e, caso se alegue produtividade, participantes e protocolo de avaliação. Até essas decisões, não há base para afirmar integração real nem ganho de produtividade.
