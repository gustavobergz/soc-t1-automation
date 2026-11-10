# Componentes de terceiros

O código do laboratório e os dados sintéticos ficam separados dos componentes de execução abaixo. A licença do emulador está em [lab/runtime/LICENSE-v86.txt](lab/runtime/LICENSE-v86.txt).

| Componente | Origem e código-fonte |
| --- | --- |
| v86 `0.5.473`, incluindo o módulo WebAssembly | [Release do pacote](https://www.npmjs.com/package/v86/v/0.5.473) · [Código e licenças](https://github.com/copy/v86) |
| SeaBIOS e SeaVGABIOS usados pelo v86 | [Imagens e configurações](https://github.com/copy/v86/tree/master/bios) · [Script de build e revisão upstream](https://github.com/copy/v86/blob/master/bios/fetch-and-build-seabios.sh) · [Licença LGPL](licenses/LGPL-3.0-SeaBIOS.txt) |
| Imagem Buildroot `buildroot-bzimage68.bin` do v86 | [Imagem upstream](https://i.copy.sh/buildroot-bzimage68.bin) · [Referências da imagem](https://github.com/copy/images#sources) · [Buildroot](https://buildroot.org/) · [Linux 6.8.12](https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.12.tar.xz) |
| Alpine Mini Root Filesystem 3.24.4 | [Distribuição oficial](https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/) · [Receitas e fontes dos pacotes](https://gitlab.alpinelinux.org/alpine/aports/-/tree/3.24-stable) |
| Alpine `linux-virt` 6.18.62-r0 e `syslinux` 6.04_pre1-r19 | [Receita do kernel](https://gitlab.alpinelinux.org/alpine/aports/-/tree/4835e466ec80d5c31c181fa130a10dc81af60c1c/main/linux-lts) · [Receita do Syslinux](https://gitlab.alpinelinux.org/alpine/aports/-/tree/d5dfca89b19916b8369b7322bfda4bf396742332/main/syslinux) |
| Runtime Go 1.25.5 | [Código](https://github.com/golang/go/tree/go1.25.5) · [Licença](licenses/Go.txt) |

Os empacotadores do laboratório são [build-assets.cjs](lab/build-assets.cjs) e [build-virtualbox.py](lab/build-virtualbox.py). Eles acrescentam o programa e o script de inicialização do laboratório aos componentes de execução. [Texto da GPL v2](licenses/GPL-2.0.txt)
