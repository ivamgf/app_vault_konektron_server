# App Vault Server — Konektron

Serviço que entrega os segredos de um cofre do App Vault a sistemas automatizados, pela
rede, sem que nenhuma senha fique gravada no servidor do sistema.

> **Estado:** versão 0.1.0 (MVP). Antes de guardar credenciais de produção, faça uma
> revisão de segurança independente (veja [Limitações](#limitações-conhecidas)).

## Como funciona

```
Equipe (Windows)                VM do cofre                            VM do sistema
┌──────────────────┐  arquivo  ┌──────────────────────────────────┐  mTLS  ┌─────────────────┐
│ App Vault desktop│ ────────▶ │ appvault_server                  │ ◀───── │ sistema Python  │
│ cadastra/edita   │  (SFTP)   │ • só lê o cofre, nunca grava     │ ─────▶ │ appvault_client │
└──────────────────┘           │ • começa trancado (unseal manual)│ segredo└─────────────────┘
                               │ • política por certificado       │
 Operador (SSH na VM) ───────▶ │ • log de auditoria encadeado     │
   unseal / seal / status      └──────────────────────────────────┘
```

1. A equipe cadastra os segredos no **App Vault desktop**, num cofre exclusivo do servidor,
   e publica o arquivo na VM do cofre.
2. O serviço inicia **trancado**. Um operador entra na VM e roda `unseal`, digitando a senha
   mestra. O serviço abre o cofre, carrega os segredos na memória e fecha o arquivo. A
   senha não é guardada.
3. O sistema se conecta com um **certificado de cliente** emitido pela CA interna (mTLS) e
   lê só os segredos que a **política** permite.
4. Toda leitura, negação e operação vai para o **log de auditoria** (sem os valores).

Depois de qualquer reinício da VM ou do serviço, ele volta a ficar trancado até um operador
rodar `unseal`. É o preço de não deixar a senha mestra gravada em disco.

## Proteções

| Ameaça | Proteção |
|---|---|
| Alguém copia o disco da VM do cofre | O arquivo do cofre continua criptografado (scrypt + AES-256-GCM). A senha mestra não está em lugar nenhum. |
| Alguém invade a VM do sistema | Ele só obtém o que a política daquele sistema permite. Revogue o certificado e troque essas credenciais. |
| Um sistema tenta ler segredos de outro | A política é conferida antes da busca, então ele nem descobre se o segredo existe. |
| Escuta ou desvio na rede | TLS 1.3 com autenticação dos dois lados, e só a CA interna é aceita. |
| Republicação de um cofre antigo (com uma senha já trocada) | O contador de geração é autenticado. O servidor recusa um arquivo anterior ao último aceito. |
| Alguém edita o log para esconder leituras | A cadeia de hashes quebra e `audit-verify` aponta a linha. Envie o log para fora da VM (veja abaixo). |
| Um cliente tenta usar a porta de operação | A porta escuta só na interface local (localhost) e exige certificado de operador. |
| Um operador tenta ler segredos pela API | Não consegue: operadores só desbloqueiam, trancam e consultam o estado. |
| Política ou lista de revogados corrompida | O servidor nega tudo até o arquivo ser corrigido. |

## Requisitos

- **VM do cofre:** Linux (recomendado) ou Windows Server, com Python **3.11+** e o pacote
  `cryptography` (`requirements-server.txt`).
- **VM do sistema:** Python 3.10+. O `appvault_client.py` não tem dependências.
- **Máquina da CA:** qualquer computador com Python e `cryptography`. De preferência,
  um que fique desligado da rede, ou ao menos fora das duas VMs.
- **App Vault desktop 1.1.0 ou mais novo** para editar o cofre do servidor. É essa versão
  que grava o contador de geração. Cofres salvos pela 1.1.0 não abrem na 1.0.0.

## Implantação

Os exemplos usam `cofre.interno` para a VM do cofre, `sistema-x` para o sistema e
`op-01` para o operador, e `<IP_DO_COFRE>` e `<IP_DO_SISTEMA>` no lugar dos endereços
IP das VMs. Troque pelos nomes e endereços reais.

### 1. Criar a CA interna (máquina da CA)

```bash
python -m appvault_server ca init --dir ./ca-appvault --name "Konektron App Vault CA"
```

A senha da CA (mínimo de 12 caracteres) protege `ca.key`. Guarde a pasta e a senha fora das
VMs, por exemplo no App Vault pessoal de quem administra a CA. Quem tiver as duas consegue
emitir certificados aceitos pelo servidor.

### 2. Emitir os certificados

```bash
# servidor: o CN e os --san precisam ser o nome/IP que o sistema usa para conectar
python -m appvault_server ca issue server   --dir ./ca-appvault --cn cofre.interno --san <IP_DO_COFRE> --out ./emitidos/servidor
# sistema (cliente): o CN é a identidade usada na política
python -m appvault_server ca issue client   --dir ./ca-appvault --cn sistema-x --out ./emitidos/sistema-x
# operador: a chave sempre tem senha
python -m appvault_server ca issue operator --dir ./ca-appvault --cn op-01   --out ./emitidos/op-01
```

Cada comando gera `<cn>.pem` (certificado) e `<cn>.key` (chave privada). Os certificados
valem 397 dias. Para listar os emitidos, use `ca list --dir ./ca-appvault`.

Leve cada arquivo **só** para onde ele é usado, por um meio seguro (SCP/SFTP):

| Arquivo | Destino |
|---|---|
| `ca.pem` | VM do cofre e VM do sistema |
| `revoked.txt` | VM do cofre |
| `servidor/cofre.interno.pem` e `.key` | VM do cofre |
| `sistema-x/sistema-x.pem` e `.key` | VM do sistema |
| `op-01/op-01.pem` e `.key` | pasta pessoal do operador na VM do cofre |

### 3. Preparar o cofre do servidor (App Vault desktop)

1. Em **Novo…**, crie um cofre **só para o servidor**, com senha mestra própria, diferente da
   do seu cofre pessoal.
2. Cadastre apenas as credenciais de que os sistemas precisam, nos ambientes certos.
3. Em **Cofre → Fazer backup…**, gere o arquivo a ser publicado, por exemplo `cofre.db`.

### 4a. Instalar no Linux (VM do cofre)

```bash
sudo useradd --system --home /var/lib/appvault --shell /usr/sbin/nologin appvault
sudo mkdir -p /opt/appvault /etc/appvault/tls /var/lib/appvault

# código: vault.py + appvault_server/ + requirements-server.txt deste repositório
sudo cp -r vault.py appvault_server requirements-server.txt /opt/appvault/
sudo python3 -m venv /opt/appvault/.venv
sudo /opt/appvault/.venv/bin/pip install -r /opt/appvault/requirements-server.txt

# configuração (a partir dos exemplos em deploy/)
sudo cp deploy/server.example.toml /etc/appvault/server.toml
sudo cp deploy/policy.example.toml /etc/appvault/policy.toml
sudo cp ca.pem revoked.txt /etc/appvault/tls/
sudo cp cofre.interno.pem /etc/appvault/tls/server.pem
sudo cp cofre.interno.key /etc/appvault/tls/server.key
sudo install -o appvault -g appvault -m 600 cofre.db /var/lib/appvault/cofre.db

# permissões: o serviço lê a configuração e grava só em /var/lib/appvault
sudo chown -R root:appvault /etc/appvault && sudo chmod -R u=rwX,g=rX,o= /etc/appvault
# a chave do servidor só o próprio serviço lê (operadores do grupo appvault não)
sudo chown appvault:appvault /etc/appvault/tls/server.key && sudo chmod 600 /etc/appvault/tls/server.key
sudo chown appvault:appvault /var/lib/appvault && sudo chmod 700 /var/lib/appvault
sudo chmod -R a+rX /opt/appvault

sudo -u appvault /opt/appvault/.venv/bin/python -m appvault_server check -c /etc/appvault/server.toml

sudo cp deploy/linux/appvault-server.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now appvault-server
journalctl -u appvault-server -f
```

No firewall, libere a porta 8443 **só** para o IP da VM do sistema, por exemplo
`sudo ufw allow from <IP_DO_SISTEMA> to any port 8443 proto tcp`. Não exponha o serviço na
internet. A porta 8444 já escuta só na interface local (localhost).

Desative a swap ou use swap criptografada, para os segredos da memória não irem parar no
disco.

### 4b. Instalar no Windows Server (VM do cofre)

1. Instale o Python 3.11+ para todos os usuários e copie `vault.py`, `appvault_server\` e
   `requirements-server.txt` para `C:\AppVaultServer\`.
2. Crie o ambiente e instale a dependência:
   ```powershell
   py -3 -m venv C:\AppVaultServer\.venv
   C:\AppVaultServer\.venv\Scripts\python.exe -m pip install -r C:\AppVaultServer\requirements-server.txt
   ```
3. Crie `C:\ProgramData\AppVaultServer\` com `server.toml`, `policy.toml`, `tls\` e o
   `cofre.db`, e ajuste os caminhos do `server.toml` para essa pasta.
4. Crie um usuário local dedicado (por exemplo `appvault-svc`), sem privilégios de
   administrador, e restrinja a pasta a ele e aos administradores:
   ```powershell
   icacls C:\ProgramData\AppVaultServer /inheritance:r /grant:r "Administradores:(OI)(CI)F" "appvault-svc:(OI)(CI)M"
   ```
5. Instale o serviço com o [WinSW](https://github.com/winsw/winsw): copie
   `deploy\windows\AppVaultServer.xml` e o `WinSW-x64.exe`, renomeado para
   `AppVaultServer.exe`, para `C:\AppVaultServer\`. Depois:
   ```powershell
   C:\AppVaultServer\AppVaultServer.exe install
   sc.exe config AppVaultServer obj= ".\appvault-svc" password= "<senha da conta>"
   Start-Service AppVaultServer
   ```
6. No Firewall do Windows, libere a porta 8443 só para o IP da VM do sistema.

### 5. Desbloquear

Na VM do cofre (por SSH ou console), com o seu certificado de operador:

```bash
python -m appvault_server unseal -c /etc/appvault/server.toml --cert ~/op-01.pem --key ~/op-01.key
python -m appvault_server status -c /etc/appvault/server.toml --cert ~/op-01.pem --key ~/op-01.key
```

O comando pede a senha da chave do operador e a senha mestra do cofre. No Linux, use o
Python do ambiente (`/opt/appvault/.venv/bin/python`). O operador precisa poder ler o
`server.toml` e o `ca.pem`: inclua-o no grupo `appvault`.

### 6. Configurar o sistema (VM do sistema)

Copie `ca.pem`, `sistema-x.pem` e `sistema-x.key` para uma pasta legível **só** pelo usuário
que roda o sistema (`chmod 600` na chave). Copie também o `appvault_client.py`.

```python
from appvault_client import AppVaultClient, SealedError

cofre = AppVaultClient("https://cofre.interno:8443",
                       ca_file="/etc/sistema-x/appvault/ca.pem",
                       cert_file="/etc/sistema-x/appvault/sistema-x.pem",
                       key_file="/etc/sistema-x/appvault/sistema-x.key")

db = cofre.get("Produção", "Banco SIAFE")
conectar(host=db.host, port=int(db.port or 5432), dbname=db.database,
         user=db.username, password=db.password, sslmode=db.extra("sslmode", "require"))
```

- `get()` lança `SealedError` se o servidor estiver trancado, `AccessDeniedError` se a
  política não permitir ou o certificado tiver sido revogado, e `NotFoundError` se o segredo
  não existir. Trate `SealedError` avisando a equipe, e não tentando sem parar.
- `list()` mostra o que o sistema pode ler, sem os valores.
- Não imprima nem registre em log os valores. O `repr()` de um `Secret` já os oculta.
- A chave do cliente fica sem senha porque o sistema roda sozinho. A proteção dela é a
  permissão do arquivo e o certificado só servir para ler o que a política permite.

## Operação

### Publicar uma versão nova do cofre

1. No App Vault desktop, edite o cofre do servidor e gere o backup.
2. Envie o arquivo para a VM e troque de uma vez (nunca edite o arquivo no lugar):
   ```bash
   sudo install -o appvault -g appvault -m 600 cofre.db /var/lib/appvault/cofre.db.novo
   sudo mv /var/lib/appvault/cofre.db.novo /var/lib/appvault/cofre.db
   ```
3. Rode `unseal` de novo. O serviço carrega o arquivo novo sem interromper as leituras. Se
   algo der errado (senha errada, arquivo corrompido, versão antiga), ele **continua
   servindo a versão anterior**.

Se o arquivo publicado for mais antigo que o último aceito, o `unseal` recusa. Para
restaurar de propósito uma versão anterior, use `unseal --accept-older`. A operação fica
registrada na auditoria.

### Trocar a senha mestra

Troque no App Vault desktop (**Cofre → Trocar senha mestra**), publique e rode `unseal` com a
senha nova. Cópias antigas do arquivo continuam abrindo com a senha antiga, por isso
apague-as.

### Revogar um certificado (sistema comprometido, operador que saiu)

```bash
python -m appvault_server ca list   --dir ./ca-appvault
python -m appvault_server ca revoke --dir ./ca-appvault --serial <série>
```

Copie o `revoked.txt` atualizado para a VM do cofre. O serviço relê o arquivo sozinho, sem
reiniciar. Se um sistema foi comprometido, **troque também as credenciais** que ele podia
ler. Revogar o certificado não desfaz o que já foi lido.

### Renovar certificados

Os certificados valem 397 dias. Antes de vencer, emita outro com `--replace`, que já revoga
o anterior. Instale o certificado novo e copie o `revoked.txt`. Para o certificado do
servidor, reinicie o serviço e rode `unseal`.

### Alterar a política

Edite o `policy.toml`. O serviço relê o arquivo sozinho. Teste antes com `check`, porque uma
política inválida faz o servidor negar tudo.

### Auditoria

```bash
sudo -u appvault /opt/appvault/.venv/bin/python -m appvault_server audit-verify -c /etc/appvault/server.toml
```

Eventos registrados: `started`, `stopped`, `unsealed`, `unseal_failed`, `unseal_rejected`,
`sealed`, `read`, `read_denied`, `read_missing`, `list`, `denied`, `config_error`,
`internal_error`. Cada um traz data e hora em UTC, identidade, IP, ambiente e nome. **Nunca**
trazem o valor do segredo.

A cadeia de hashes detecta edições, mas quem tiver controle total da VM pode reescrever a
cadeia inteira. Por isso cada evento também sai no journald (Linux) ou no log do WinSW
(Windows). Encaminhe esses logs para um servidor de logs fora da VM do cofre, por exemplo
com rsyslog ou o agente do seu SIEM.

### Backup

Faça backup do cofre a partir do App Vault desktop, que é a fonte, e dos arquivos de
`/etc/appvault` e da pasta da CA. O `state.json` e o `audit.log` da VM também merecem cópia.
Ao restaurar a VM, o `state.json` antigo pode exigir `unseal --accept-older`.

## API

Todas as rotas exigem certificado de cliente da CA interna e respondem em JSON.

| Rota | Quem usa | Resposta |
|---|---|---|
| `GET /v1/health` | qualquer certificado válido | `{"sealed": bool}` |
| `GET /v1/secrets` | cliente | `{"secrets": [{"environment", "name", "kind"}]}` |
| `POST /v1/secret` `{"environment", "name"}` | cliente | `{"secret": {...}}` com os campos do App Vault |
| `GET /v1/sys/status` | operador, só na própria máquina | estado, geração e número de segredos |
| `POST /v1/sys/unseal` `{"password", "accept_older"}` | operador, só na própria máquina | estado |
| `POST /v1/sys/seal` | operador, só na própria máquina | estado |

Códigos de erro: `400` (requisição inválida), `403` (sem permissão, revogado ou senha mestra
incorreta), `404`, `409` (versão antiga do cofre ou desbloqueio em andamento), `413`, `422`
(cofre ilegível ou adulterado) e `503` (trancado ou política indisponível).

## Limitações conhecidas

- **Sem revisão externa.** O código usa só bibliotecas consolidadas (`ssl` do Python e
  `cryptography`), mas o desenho e a implementação ainda não foram auditados por terceiros.
- **Memória.** Enquanto o servidor está desbloqueado, os segredos ficam na memória do
  processo, e o Python não garante apagá-los. Quem tiver root ou administrador na VM do cofre
  consegue lê-los. Por isso a VM deve rodar só este serviço e ter poucos acessos.
- **Provedor da VPS.** O provedor tem acesso físico às VMs, inclusive à memória. Avalie se
  isso é aceitável para os dados em questão.
- **Revogação manual.** A lista de revogados precisa ser copiada para a VM a cada revogação.
  Não há CRL nem OCSP.
- **Unseal com uma senha só.** Ainda não há divisão da senha entre várias pessoas (Shamir).
- **Somente leitura e um servidor.** Não há gravação pela API, alta disponibilidade nem
  credenciais dinâmicas. Se surgir essa necessidade, o OpenBao é o caminho.
- **O `state.json` fica na própria VM.** Quem tiver acesso de gravação nela pode apagar o
  estado e publicar um cofre antigo. A proteção contra versões antigas vale contra erros e
  contra quem só consegue publicar arquivos, não contra o administrador da VM.
