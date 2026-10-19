import os
import sys

# vault.py fica na raiz do projeto, ao lado deste pacote.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from appvault_server.cli import main  # noqa: E402

sys.exit(main())
