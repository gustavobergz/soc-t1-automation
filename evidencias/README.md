# Evidências históricas do TCC

O arquivo [Evidencias_SOC_TCC_20261116.zip](Evidencias_SOC_TCC_20261116.zip) é o pacote original citado nos Apêndices A e D do TCC. Ele foi publicado sem alterações e preserva as fontes da revisão `0184c785f73ce15a36ffbd93ac8b395d461679a2`.

SHA256 do ZIP: `5fa05868b2b4cba7bc91f0c37e988170c7357e391103dead8ab2be31ab839560`.

Contém os logs sintéticos originais, o script de análise, os CSVs derivados, o resumo, registros de testes, a figura de topologia e os manifestos. As fontes são idênticas a `logs/clinica-demo.jsonl` e `logs/clinica-investigacao-205k.jsonl.gz` do repositório. Datas, resultados de testes e versões dentro do ZIP descrevem o acervo histórico; não são atualizados por novas execuções.

## Reproduzir a análise

Com Python 3.9 ou superior, execute na raiz do repositório:

```powershell
python scripts/analisar_evidencias.py
```

O ponto de entrada confere o SHA256, extrai uma cópia temporária e executa o algoritmo original incluído no ZIP, usando apenas a biblioteca padrão. Os arquivos recalculados ficam em `evidencias/recalculado/`, ignorada pelo Git. Para escolher outra pasta, use `--output CAMINHO`. O ZIP e os logs versionados permanecem intactos.

Também é possível seguir literalmente o Apêndice A: baixar e extrair o ZIP, abrir a pasta extraída e executar `python scripts/analisar_evidencias.py`. Nesse caso, o script do próprio pacote grava os resultados na pasta extraída.

## Referência dos resultados

- 12 rodadas: 6 fixture, 3 manuais, 2 Ollama e 1 falha induzida.
- Detector: 3 VP, 1 FP, 1 VN e 3 FN em 8 casos.
- 5 contenções com aprovação e 5 liberações por comando (`rollback`). A expiração de 45 s existe no código, mas não ocorreu neste acervo.
- Triagens Ollama: 35,452 s e 47,128 s.
- Nas 6 triagens fixture, 5 registros usam `soc-clinic-1` e 1 usa `soc-clinic-3`.
- MTTR: 1,343 s no grupo fixture com contenção e 47,795 s no caso Ollama contido.
- Base de investigação: 205.000 eventos sintéticos.

O conjunto não constitui comparação pareada com analistas humanos. As novas rodadas do aplicativo permanecem separadas desse histórico.
