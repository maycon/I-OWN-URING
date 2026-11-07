# Script de Apresentação — What EDRs Don't See
**I-OWN-U-RING · Hack N' Roll · 50 minutos**

---

## S1 · Cover · 0:30

Boa noite pessoal. Antes de começar, uma pergunta rápida de mãos: quem aqui usa um EDR no ambiente de trabalho? E quem confia que esse EDR vai detectar um shellcode bem escrito?

*[pausa]*

Bom, esse número vai mudar daqui a cinquenta minutos.

---

## S2 · Speaker · 1:00

Meu nome é Maycon Vitali, sou o fundador da Hack N' Roll. Trabalho com segurança ofensiva há mais de vinte anos — comecei com envenenamento de DNS quando isso ainda era novidade, passei por exploração web, mobile, e hoje estou aqui falando de bypass de EDR via subsistema de I/O do kernel Linux.

Não sou pesquisador de kernel. Sou pentester. E foi exatamente essa perspectiva que me fez ver esse vetor de um ângulo diferente.

---

## S3 · Agenda · 0:30

Vamos começar mostrando como um EDR Linux enxerga um shellcode tradicional. Depois eu explico como o io_uring funciona e por que ele é um problema pra esse modelo. Na sequência, a implementação completa em três camadas. Demo ao vivo. E termino com o que o blue team pode fazer hoje.

---

## S4 · EDR Model · 1:30

A maioria dos EDRs Linux monitora o kernel em três pontos. O primeiro é o `raw_tracepoint/sys_enter` — um hook em eBPF que dispara toda vez que um processo faz uma chamada de sistema. Qualquer `openat`, qualquer `connect`, qualquer `read` — o EDR vê. Falco e a maioria dos sensores básicos ficam aqui.

O segundo são kprobes em funções internas como `do_sys_openat2` e `ksys_read`. Um hook direto na implementação do syscall, mais profundo que o sys_enter. Wazuh opera nessa camada.

O terceiro são hooks de LSM — Linux Security Module — dentro do VFS. `security_file_open` para abertura, `security_file_permission` para read e write. Disparam independentemente de como a operação chegou ao VFS.

O problema que vou mostrar hoje afeta as duas primeiras camadas. E afeta muito mais EDRs do que você imagina.

---

## S5 · Traditional Shellcode · 1:30

Esse é um shellcode de reverse shell clássico rodando sob strace. Você consegue ver claramente: `socket`, `connect`, `dup2` três vezes, `execve`. São seis syscalls detectáveis, na sequência exata que todo EDR conhece.

Isso é um IoC tão clássico que qualquer ferramenta decente tem essa assinatura catalogada. O EDR vai detectar antes mesmo do processo sair da memória.

*[pausa curta]*

Então a pergunta natural é: e se o I/O nunca passasse por uma syscall?

---

## S6 · Question · 1:00

*[slide na tela, sem pressa]*

"What if I/O never goes through a syscall?"

Isso é mais do que uma pergunta retórica. É exatamente o que o io_uring torna possível desde o kernel 5.1, lançado em março de 2019.

Sete anos. Esse vetor existe há sete anos.

---

## S7 · Why io_uring · 2:00

O io_uring foi criado pelo Jens Axboe para resolver um problema legítimo de performance: o custo de contexto de cada syscall em operações de I/O intensivo é significativo. A solução foi criar um mecanismo de comunicação via memória compartilhada entre userspace e kernel.

Você faz o setup uma vez, mapeia as regiões de memória, e a partir daí submete operações escrevendo diretamente nos rings. O kernel processa internamente e devolve os resultados pelo mesmo canal.

Cronologicamente: `CONNECT` chegou no kernel 5.5, `OPENAT` e `READ` e `SEND` no 5.6, e `SOCKET` no 5.19. A partir do kernel 5.19 você tem tudo que precisa para uma missão completa de exfiltração sem um único `openat()` ou `connect()` visível.

---

## S8 · SQ/CQ Architecture · 2:00

A arquitetura é elegante. Duas filas circulares mapeadas em memória compartilhada. O Submission Queue, onde userspace escreve os comandos. O Completion Queue, onde o kernel deposita os resultados.

Depois do setup inicial, que envolve um `io_uring_setup` e dois mmaps — em kernels modernos com `IORING_FEAT_SINGLE_MMAP` o SQ e CQ ring compartilham o mesmo mapeamento — a comunicação é toda via ponteiros. Sem syscalls para cada operação.

O único ponto de contato visível depois do setup é o `io_uring_enter`, que submete N operações de uma vez e aguarda completions. Uma syscall, N operações. É aí que o bypass acontece.

---

## S9 · SQE Structure · 1:30

Cada operação é descrita por uma estrutura de 64 bytes: o SQE, Submission Queue Entry. Os campos mais importantes são o `opcode` — que define a operação —, o `fd`, o ponteiro para o buffer via `addr`, o tamanho via `len`, e o `user_data` que você usa pra correlacionar qual operação completou.

Um detalhe importante: para `CONNECT`, o tamanho do endereço não vai em `len`. Vai em `off`, que funciona como `addr2` nesse contexto. Esse é um dos bugs mais comuns na implementação.

O kernel retorna o resultado no CQE, no campo `res`. Positivo é sucesso, negativo é `-errno`.

---

## S10 · Opcodes · 1:30

Aqui estão os opcodes relevantes com a versão mínima de kernel pra cada um. O ponto importante é que a versão que importa para a missão completa é o 5.19, quando o `IORING_OP_SOCKET` foi adicionado.

Se você tiver um alvo com kernel entre 5.6 e 5.18, você ainda consegue fazer openat e read via io_uring, mas vai precisar de um socket por syscall direta. Compatibilidade importa — o builder verifica isso automaticamente via `requires_kernel`.

---

## S11 · EDR Diff · 3:00

*[pausa ao mostrar o slide]*

Do lado esquerdo: o que o EDR registra. O log do `sys_enter`. `io_uring_setup`. Três `mmap`. Um único `io_uring_enter` submetendo todas as operações de uma vez. `close`. Fim do log. Processo limpo.

Do lado direito: o que realmente aconteceu dentro daquele `io_uring_enter`.

*[pausa]*

`openat` no `/etc/shadow`. `read`. `socket`. `connect` pro C2. `send` com os dados. Tudo invisível.

Seis operações de I/O. Zero syscalls individuais de I/O visíveis. O EDR sabe que o processo usou io_uring. Não sabe o que ele fez.

Isso não é um bypass de evasão. Isso é uma lacuna arquitetural no modelo de detecção. O EDR está monitorando a entrada correta, mas as operações nunca passam por lá.

*[pausa longa]*

Vamos ver como isso funciona internamente.

---

## S12 · Kernel Path · 2:00

No caminho tradicional, um read começa passando pelo `raw_tracepoint/sys_enter` — é aí que o EDR dispara. Depois segue por `sys_read`, `ksys_read`, `vfs_read`, e finalmente pelo hook de LSM `security_file_permission`. Quem monitora em LSM também vê.

No caminho do io_uring, o `io_uring_enter` vai para `io_submit_sqes`, depois `io_issue_sqe`, depois `io_read`, que chama o mesmo `vfs_read`. O hook de LSM `security_file_permission` dispara do mesmo jeito.

O que não existe no caminho do io_uring é o passo do `sys_enter`. Por isso ferramentas que monitoram apenas syscalls são cegas. E por isso LSM hooks são a resposta correta.

---

## S13 · Layers · 1:00

A implementação está organizada em três camadas independentes. Layer 0 faz o bootstrap — os únicos syscalls visíveis da missão inteira. Layer 1 é o runtime engine reutilizável — a mecânica de SQE e CQE. Layer 2 é a missão em si — gerada automaticamente pelo builder a partir de um YAML.

Vamos ver cada uma.

---

## S14 · Layer 0 · 2:30

O bootstrap é simples em conceito: um `io_uring_setup`, dois mmaps, e depois aritmética de ponteiros a partir do que o kernel retornou nos `params`.

Esse passo de aritmética de ponteiros é crítico. Os offsets internos dos rings — onde fica o `sq_tail`, o `cq_head`, o array de SQEs — são retornados pelo kernel em `io_uring_params.sq_off` e `cq_off`. Você não hardcodeia esses valores. Você os computa em runtime a partir do que o kernel te entregou.

Isso serve dois propósitos: funciona em qualquer versão de kernel sem recompilação, e o shellcode não tem constantes que denunciam seu propósito numa análise estática.

Depois do bootstrap, `sq_ring` e `sqes` são ponteiros para memória compartilhada com o kernel. O próximo syscall visível só vai aparecer no io_uring_enter.

---

## S15 · Layer 1 · 2:00

O runtime é essa mecânica aqui. Para submeter: pegue o próximo slot no SQ ring usando `sq_tail & mask`, preencha os campos do SQE — opcode, fd, addr, len — e incremente o tail. O kernel vai pegar quando você chamar `io_uring_enter`.

Para consumir: aguarde `cq_head != cq_tail`, leia o CQE no índice `cq_head & mask`, extraia o `res`, e avance o head.

Todo o resto da implementação é chamar esse padrão com opcodes diferentes. O loop nunca muda. O que muda é o que você coloca nos campos.

---

## S16 · Layer 2 · 2:00

A missão faz exatamente cinco operações, todas via io_uring. A primeira é um `IORING_OP_OPENAT` com o path do arquivo e `O_RDONLY`. O resultado — o file descriptor — flui para a segunda operação, o `IORING_OP_READ`.

No meio, socket e connect. No final, `IORING_OP_SEND` com o buffer e o número de bytes que o read retornou.

Com `IOSQE_IO_LINK`, você encadeia as cinco SQEs e submete tudo em um único `io_uring_enter` — se qualquer operação falha, as downstream são canceladas. Na PoC fazemos cinco `io_uring_enter` separados por simplicidade, mas o resultado é o mesmo: zero `openat`, zero `read`, zero `connect`, zero `send` no strace.

---

## S17 · SQPOLL · 1:30

Existe um modo ainda mais extremo: SQPOLL. Com a flag `IORING_SETUP_SQPOLL`, o kernel spawna uma thread dedicada que fica polling o SQ ring. Após o setup, você escreve diretamente no ring e incrementa o tail. Sem `io_uring_enter`.

Depois do bootstrap, zero syscalls de I/O. Completamente invisível até para quem monitora o `io_uring_enter`.

A limitação: precisa de privilégio, ou de um kernel 5.11+ onde o `CAP_SYS_NICE` não é mais necessário. Ubíquo em servidores modernos com kernel 6.x. Para ambientes containerizados é o modo ideal.

---

## S18 · PoC Results · 2:00

Testado no kernel 6.14.0, aqui estão os resultados. Lado esquerdo, shellcode tradicional de exfiltração: quatro syscalls de I/O no strace — `openat`, `read`, `write`, `close`. Lado direito, io_uring: `io_uring_setup`, dois mmaps, cinco `io_uring_enter`. Nenhum `openat`, `read`, `connect` ou `send` visível.

O `/etc/shadow` foi lido, conectou no C2, os dados chegaram. E o EDR que monitora `sys_enter` não viu nada além de um processo que usou io_uring.

---

## S19 · Detection Matrix · 2:00

A tabela resume o que testamos. Ferramentas baseadas em `sys_enter` — a maioria dos EDRs open source e muitos comerciais — são completamente cegas ao io_uring internamente.

Ferramentas com LSM hooks detectam porque `security_file_open` dispara dentro do VFS independentemente de como a operação chegou lá.

CrowdStrike e Elastic ficam no amarelo porque dependem de configuração e versão. Testate no seu ambiente antes de assumir cobertura.

seccomp negando `io_uring_setup` é o bloqueio mais simples e mais efetivo disponível hoje.

---

## S20 · Blue Team · 2:30

Para quem defende, três recomendações em ordem de facilidade de implementação.

A mais rápida: seccomp para workloads containerizados. A maioria dos pods Kubernetes não usa io_uring legitimamente. Uma linha no seccomp profile bloqueia o setup inteiro.

A correta arquiteturalmente: migrar detecção para LSM hooks. `security_file_open`, `security_socket_connect`. Esses hooks disparam independentemente do caminho de submissão. Tetragon com TracingPolicy tem essa capacidade hoje.

A mais drástica: `kernel.io_uring_disabled=2` desabilita io_uring no sistema inteiro. Cuidado: PostgreSQL 14+ e alguns workloads de storage usam io_uring ativamente.

---

## S21 · Schema · 1:30

E isso aqui é tudo que você precisa para definir uma missão. Um YAML com o C2, e a sequência de operações. O builder resolve o resto: qual SQE corresponde a cada op, como os resultados fluem entre elas, onde ficam os offsets de IP e porta no binário final.

A missão completa de exfiltração do shadow cabe em vinte linhas. O builder gera um `shellcode.bin` pronto pra injetar e um `shellcode.h` com os offsets patcháveis.

---

## S22 · Release · 1:30

E com isso, vou anunciar que o repositório está público agora.

I-OWN-U-RING. Framework completo: shellcode em x64, builder YAML, framework de teste, paper técnico, e a matriz de detecção documentada.

O que eu quero da comunidade: uma variante abaixo de 500 bytes usando SQPOLL, um port pra ARM64, e expansão da matriz com EDRs comerciais que vocês testarem.

`github.com/maycon/i-own-u-ring`

---

## S23 · DEM🔵 · 6:00

Agora a demo ao vivo.

*[abrir dois terminais]*

Terminal um, o listener:

```
nc -lvp 4444
```

Terminal dois, o runner com strace:

```
sudo strace ./runner shellcode.bin 127.0.0.1 4444
```

*[executar, mostrar o strace rolando]*

Vejam o que aparece. `io_uring_setup`. Dois mmaps. E aqui — cinco `io_uring_enter`. Cada um deles esconde uma operação: openat, read, socket, connect, send.

*[mostrar o nc recebendo dados]*

E aqui no listener — o conteúdo do `/etc/shadow`.

*[pausa]*

Sem um único `openat`. Sem um `connect`. O EDR que monitora `sys_enter` não viu nada disso acontecer.

*[fechar os terminais]*

---

## S24 · Key Takeaways · 2:00

Três coisas pra sair daqui sabendo.

Um: EDRs baseados em `sys_enter` são cegos ao io_uring. Não é bug. É uma lacuna arquitetural. As operações de I/O acontecem, só não passam pelo ponto que eles monitoram.

Dois: a detecção correta fica no VFS. `security_file_open`, `security_file_permission` — disparam independentemente do caminho. Quem não tem LSM hooks tem um ponto cego.

Três: a mitigação existe hoje. seccomp, LSM, `io_uring_disabled`. Não espere o próximo CVE para implementar.

---

## S25 · Q&A · 5:30

Obrigado. Perguntas?

*[referência para perguntas frequentes na tela]*

