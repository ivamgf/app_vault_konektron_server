# App Vault Protection — Konektron

Aplicativo desktop para guardar credenciais de plataformas de dados (FTP/SFTP, APIs,
painéis web, bancos de dados, SSH, nuvem…) **separadas por ambiente** (Produção,
Homologação, Desenvolvimento ou ambientes que você criar). Tudo fica num único arquivo
local criptografado.

## Download e instalação (Windows)

**Requisitos:** Windows 10 ou 11 de 64 bits e cerca de 40 MB livres. Não é preciso ter
Python nem permissão de administrador.

> **Acesso:** o repositório [ivamgf/app_vault_konektron_server](https://github.com/ivamgf/app_vault_konektron_server) é
> privado. Para baixar o instalador, você precisa de uma conta no GitHub com acesso de
> leitura a ele; peça ao responsável. Links das Releases só funcionam para quem está
> logado e tem esse acesso.

### 1. Baixar

**Pelo navegador**

1. Entre no GitHub com a sua conta e abra a
   [versão mais recente](https://github.com/ivamgf/app_vault_konektron_server/releases/latest)
   (ou, no repositório, **Releases → Latest**).
2. Em **Assets**, baixe os dois arquivos:
   - `AppVaultProtection-Setup-<versão>.exe` (o instalador)
   - `SHA256SUMS.txt` (o código de verificação)

**Pelo GitHub CLI** (opcional)

```powershell
gh auth login
gh release download --repo ivamgf/app_vault_konektron_server --pattern "*"
```

Baixe sempre da página de Releases. Não use cópias recebidas por e-mail, chat ou
pendrive.

### 2. Conferir a integridade

No PowerShell, na pasta do download:

```powershell
(Get-FileHash .\AppVaultProtection-Setup-*.exe -Algorithm SHA256).Hash
Get-Content .\SHA256SUMS.txt
```

O primeiro comando mostra o código do arquivo baixado; o segundo, o código publicado.
Os dois precisam ser iguais (sem diferenciar maiúsculas de minúsculas). Se forem
diferentes, **não instale**: apague o arquivo e baixe de novo.

### 3. Instalar

1. Dê dois cliques em `AppVaultProtection-Setup-<versão>.exe`.
2. Se aparecer "O Windows protegeu o computador", é porque o instalador ainda não tem
   assinatura digital. Depois de conferir o código do passo 2, clique em
   **Mais informações → Executar assim mesmo**.
3. Siga o assistente. Se quiser, marque **Criar um atalho na área de trabalho**.
4. Ao final, o app abre. Depois, ele fica no **Menu Iniciar → App Vault Protection**.

O programa é instalado só para o seu usuário, em
`%LOCALAPPDATA%\Programs\App Vault Protection`.

### Atualizar

Baixe e confira a versão nova (passos 1 e 2) e instale por cima. Se o app estiver
aberto, o instalador pede para fechá-lo. Os cofres são mantidos.

> **A partir da 1.1.0**, o app grava no cofre um contador de versões, usado pelo
> [App Vault Server](docs/SERVIDOR.md). Um cofre salvo pela 1.1.0 **não abre na 1.0.0**,
> que acusa "Falha de integridade". Atualize todos os computadores que usam o mesmo cofre.

A versão instalada aparece em **Ajuda → Sobre**.

### Desinstalar

**Configurações → Aplicativos → Aplicativos instalados → App Vault Protection →
Desinstalar.**

Os cofres ficam em `%LOCALAPPDATA%\AppVaultProtection` e **não** são apagados na
desinstalação. Apague essa pasta manualmente só se tiver certeza de que não precisa mais
deles.

### Instalação silenciosa (equipe de TI)

O instalador aceita os parâmetros padrão do Inno Setup. Ele instala por usuário, então
deve rodar **na sessão do próprio usuário**, não como SYSTEM:

```powershell
# instalar (adicione /TASKS="desktopicon" para criar o atalho na área de trabalho)
.\AppVaultProtection-Setup-<versão>.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART

# desinstalar
& "$env:LOCALAPPDATA\Programs\App Vault Protection\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
```

### Levar o cofre para outro computador

O cofre é um único arquivo e funciona em qualquer máquina com o app instalado.

1. No computador antigo: **Cofre → Fazer backup…**
2. Leve o arquivo por um meio confiável. Ele é criptografado, mas evite deixar cópias
   pelo caminho.
3. No computador novo, na tela inicial: **Abrir…**, escolha o arquivo e digite a senha
   mestra.

### Problemas comuns

| Situação | O que fazer |
|---|---|
| Página de Releases não abre / erro 404 | Você não está logado ou não tem acesso ao repositório. Peça acesso. |
| Códigos SHA-256 diferentes | Não instale. Baixe de novo pela página de Releases; se persistir, avise o responsável. |
| Antivírus bloqueou o instalador | Confira o SHA-256 e avise a equipe de TI; não desative o antivírus por conta própria. |
| "Senha mestra incorreta" | Confira o Caps Lock e o layout do teclado. Após erros seguidos, o app espera alguns segundos. |
| Esqueceu a senha mestra | Não há recuperação. Restaure um backup cuja senha você conheça. |
| "Falha de integridade" ao abrir | O arquivo foi alterado ou corrompido fora do app. Restaure um backup. |

## Primeiro uso

1. A tela **"Novo cofre"** cria o arquivo no local padrão
   (`%LOCALAPPDATA%\AppVaultProtection\cofre.db`), uma pasta acessível só ao seu usuário.
2. Defina a senha mestra (mínimo de 12 caracteres; uma frase longa é melhor) e confirme.
3. Clique em **Criar cofre**. Nas próximas vezes, o app pede só a senha.

A senha mestra **não tem recuperação**. Se ela for esquecida, os dados se perdem.
Guarde-a de cabeça ou num gerenciador de senhas pessoal, nunca em arquivos,
scripts, e-mails ou chats.

Use sempre o seu usuário normal, nunca "executar como administrador".

### Usar outro arquivo de cofre

Pela tela inicial, com os botões **Abrir…** e **Novo…**. O app nunca recebe a senha
mestra por parâmetro, variável de ambiente ou arquivo, e isso é intencional: ela só é
digitada na tela de desbloqueio.

### Onde **não** guardar o cofre

- Dentro deste repositório ou de qualquer pasta versionada. O `.gitignore` ignora
  `*.db`, mas não conte só com isso.
- Pastas compartilhadas de rede ou de outros usuários.
- Pastas sincronizadas (OneDrive, Google Drive...), a menos que essa seja uma decisão
  consciente. O arquivo é criptografado, mas sincronizar espalha cópias que ficam
  presas à senha mestra da época em que foram feitas.

Para backups, use **Cofre → Fazer backup…** e guarde a cópia num local restrito.

## Funcionalidades

- **Cadastrar, visualizar, editar e excluir** segredos. Os campos mudam conforme o tipo:
  | Tipo | Campos |
  |---|---|
  | FTP / SFTP | host, porta, usuário, senha |
  | API | URL base, client ID, client secret, API key/token |
  | Painel / Web | URL, usuário, senha |
  | Banco de dados | host, porta, banco/schema, usuário, senha |
  | SSH / Servidor | host, porta, usuário, senha, chave privada/passphrase |
  | Nuvem | console/região, access key ID, senha, secret access key |
  | Outro | todos os campos |

  Também há **campos extras** (chave/valor, opcionalmente secretos) e observações.
- **Ambientes**: criar, renomear, excluir (só se estiver vazio). Filtro por ambiente na
  lateral, com contagem e cor (produção em vermelho).
- **Duplicar** um segredo para outro ambiente (ex.: copiar a configuração de homologação
  para produção e trocar só a senha).
- Busca por nome, host, URL, usuário; filtro por tipo; ordenação por coluna.
- Gerador de senhas, troca de senha mestra e backup.
- Atalhos: `Ctrl+N` novo, `Ctrl+F` buscar, `Ctrl+L` bloquear, `Enter` editar, `Del` excluir.

## Segurança

Núcleo em [vault.py](vault.py) (formato v2):

| Proteção | Como |
|---|---|
| Senha mestra | scrypt (N=2¹⁷, r=8, ~128 MiB), mínimo de 12 caracteres |
| Criptografia | AES-256-GCM por segredo, com nonce aleatório a cada gravação |
| Nomes e ambientes ocultos | ID da linha = HMAC(ambiente + nome); lista de ambientes criptografada |
| Troca de linhas | o ID entra como AAD do GCM |
| Cabeçalho adulterado (KDF, salt) | o cabeçalho entra como AAD do embrulho da chave |
| Linhas apagadas ou restauradas por fora | manifesto HMAC de todo o conteúdo, verificado ao abrir |
| Troca de senha mestra | gera uma chave de dados **nova** e recriptografa tudo |
| Dados apagados | `PRAGMA secure_delete` sobrescreve com zeros |
| Permissões do arquivo | criação exclusiva; ACL só do usuário (Windows) ou `chmod 600` |
| Parâmetros de KDF hostis | limites validados ao abrir (evita downgrade e estouro de memória) |

Na interface:

- **Bloqueio automático** após 5 min sem uso, e manual (`Ctrl+L`). Ao bloquear, as
  chaves são descartadas e todas as janelas abertas são fechadas.
- **Área de transferência**: o conteúdo copiado é limpo após 30 s (só se ainda for o
  mesmo). No Windows, fica fora do histórico (Win+V) e da sincronização na nuvem.
- Segredos sempre mascarados; "Mostrar" volta a ocultar sozinho após 20 s.
- Atraso crescente após senhas mestras erradas.
- Ao trocar o tipo de um segredo, os campos que deixaram de valer não são gravados.

Na distribuição:

- O instalador é gerado no GitHub Actions a partir do código da tag, não na máquina de
  alguém, e cada release publica o SHA-256 do instalador.
- As dependências de build têm versões fixas (`requirements-build.txt`).
- O executável não usa UPX nem o modo "arquivo único", que costumam gerar falsos
  positivos em antivírus.
- Assinatura de código suportada (ver abaixo); recomendada antes de distribuir em larga escala.

### Limitações conhecidas

- O Python não permite apagar chaves e senhas da memória com garantia. Bloqueie o
  cofre quando não estiver usando. Contra quem já tem acesso à memória da máquina
  (malware, administrador), nenhum cofre local resolve.
- No app desktop, restaurar o arquivo **inteiro** a uma versão antiga não é detectado (o
  manifesto detecta só alterações parciais). O App Vault Server detecta, porque guarda a
  última versão que aceitou.
- O atraso entre tentativas vale só para a interface. Contra força bruta offline, a
  proteção é o custo do scrypt somado à força da senha mestra.
- Cofres no formato v1 (o `vault.py` original) não abrem nesta versão.
- Ainda não há atualização automática: novas versões são baixadas e instaladas manualmente.

### Backup

Sem a senha mestra, os dados são irrecuperáveis. Use **Cofre → Fazer backup…**. O
backup continua criptografado, mas abre com a senha mestra **da época em que foi feito**.

## Uso em servidores (App Vault Server)

Para sistemas automatizados que precisam de credenciais sem ninguém para digitar a
senha, há o **App Vault Server** ([appvault_server/](appvault_server/)). Ele roda numa VM
separada, Linux ou Windows, e entrega os segredos de um cofre do App Vault por mTLS. O
sistema usa a biblioteca [appvault_client.py](appvault_client.py). O servidor começa
trancado e é desbloqueado por um operador; cada sistema só lê o que a política permite, e
toda leitura vai para um log de auditoria.

Implantação, CA interna, operação e limitações: **[docs/SERVIDOR.md](docs/SERVIDOR.md)**.

## Desenvolvimento

Requer Python 3.10+ com Tkinter (já incluso no instalador oficial do Windows).

### Executar a partir do código

No PowerShell, dentro da pasta do projeto:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Chamar o `python.exe` do ambiente virtual dispensa o `Activate.ps1`. Se preferir
ativar o ambiente e o PowerShell bloquear o script, libere só para a sessão atual
(`Set-ExecutionPolicy -Scope Process RemoteSigned`). **Não** altere a política da
máquina inteira nem use `Unrestricted`.

### Testes

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Os testes criam cofres temporários com senhas fictícias e os apagam ao terminar. Eles
nunca tocam no seu cofre real.

### Gerar o executável e o instalador localmente

Pré-requisito: Inno Setup 6 (`winget install JRSoftware.InnoSetup`).

```powershell
.\build.ps1                  # testes + executável + instalador
.\build.ps1 -SkipInstaller   # só o executável (dist\AppVaultProtection\)
```

O resultado fica em `dist\installer\`: o instalador e o `SHA256SUMS.txt`. O script usa
um ambiente virtual próprio (`.venv-build`) com as versões de `requirements-build.txt`.

| Arquivo | Função |
|---|---|
| [version.py](version.py) | nome e versão (fonte única) |
| [app_vault.spec](app_vault.spec) | configuração do PyInstaller |
| [installer/app_vault.iss](installer/app_vault.iss) | script do Inno Setup |
| [build.ps1](build.ps1) | build completo |
| [tools/make_icon.py](tools/make_icon.py) | gera `assets/app.ico` |
| [.github/workflows/release.yml](.github/workflows/release.yml) | build e publicação no GitHub |
| [appvault_server/](appvault_server/) | App Vault Server (não entra no instalador) |
| [appvault_client.py](appvault_client.py) | cliente do servidor, para os sistemas |
| [deploy/](deploy/) | exemplos de configuração, unidade systemd e serviço Windows |

### Publicar uma versão

1. Atualize `__version__` em [version.py](version.py) (ex.: `1.1.0`) e faça o commit.
2. Crie e envie a tag correspondente:

   ```powershell
   git tag v1.1.0
   git push origin v1.1.0
   ```

3. O workflow **Release** roda os testes, gera o instalador e publica a Release com o
   instalador e o `SHA256SUMS.txt`. Se a tag for diferente da versão em `version.py`,
   o workflow falha.

Para gerar só um instalador de teste, sem publicar, use **Actions → Release → Run
workflow**. O instalador fica disponível como artefato da execução.

Em repositório privado, as Releases ficam visíveis só para quem tem acesso a ele. Além
disso, o GitHub Actions consome minutos da cota da conta, e os executores Windows contam
em dobro.

### Assinatura de código (opcional, recomendada)

Com um certificado de assinatura de código (`.pfx`), o `build.ps1` assina o executável
e o instalador automaticamente:

- **Localmente:** defina `CODESIGN_PFX_PATH` e `CODESIGN_PFX_PASSWORD` na sessão.
- **No GitHub:** cadastre os secrets `CODESIGN_PFX_BASE64` (o `.pfx` em base64) e
  `CODESIGN_PFX_PASSWORD` em Settings → Secrets and variables → Actions.

Nunca faça commit do certificado nem da senha dele.
