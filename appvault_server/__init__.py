"""
App Vault Server — entrega segredos de um cofre do App Vault a sistemas, pela rede.

Somente leitura: os segredos são cadastrados no App Vault desktop e o arquivo do cofre
é publicado no servidor. O servidor começa trancado; um operador digita a senha mestra
(``python -m appvault_server unseal``) e os segredos ficam só na memória do processo.

Cada sistema se identifica por um certificado de cliente (mTLS) emitido pela CA
interna (``python -m appvault_server ca ...``) e só lê o que a política permite.
Toda leitura vai para um log de auditoria encadeado por hash.

Veja docs/SERVIDOR.md.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
