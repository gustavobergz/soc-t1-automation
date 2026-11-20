"""Executa a análise original do pacote de evidências do TCC, sem alterar o ZIP."""
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile
import argparse
import hashlib
import runpy
import shutil

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "evidencias" / "Evidencias_SOC_TCC_20261116.zip"
EXPECTED_SHA256 = "5fa05868b2b4cba7bc91f0c37e988170c7357e391103dead8ab2be31ab839560"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "evidencias" / "recalculado")
    args = parser.parse_args()
    if hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise SystemExit("O ZIP não corresponde ao pacote original de evidências.")
    with TemporaryDirectory(prefix="soc-tcc-evidencias-") as temporary:
        extracted = Path(temporary)
        with ZipFile(ARCHIVE) as archive:
            for entry in archive.infolist():
                if not (extracted / entry.filename).resolve().is_relative_to(extracted.resolve()):
                    raise SystemExit("Caminho inválido no pacote de evidências.")
            archive.extractall(extracted)
        # O algoritmo e os dados originais permanecem congelados dentro do pacote.
        runpy.run_path(str(extracted / "scripts" / "analisar_evidencias.py"), run_name="__main__")
        args.output.mkdir(parents=True, exist_ok=True)
        for source in (extracted / "resultados").iterdir():
            if source.is_file():
                shutil.copyfile(source, args.output / source.name)
        shutil.copyfile(extracted / "sha256.json", args.output / "sha256.json")


if __name__ == "__main__":
    main()
