# Port Scanner em Python

## Descrição
Ferramenta de escaneamento de portas escrita em Python 3 para identificar portas abertas, fechadas ou filtradas em um host específico, suportando protocolos TCP e UDP. Inclui detecção de serviços bem conhecidos e tentativa de banner grabbing para portas TCP.

## Funcionalidades Implementadas
- **Escaneamento de Host**: Escaneia portas de um único host (IPv4 ou IPv6).
- **Intervalo de Portas**: Permite definir o intervalo de portas via argumentos `--start` e `--end`.
- **Protocolos Suportados**: Escaneamento TCP e UDP (selecionável com `--protocol`).
- **Well-Known Ports**: Associa portas conhecidas a serviços (ex.: 80 → HTTP).
- **Estado das Portas**: Identifica se as portas estão abertas, fechadas ou filtradas.
- **Banner Grabbing**: Tenta capturar banners de serviços TCP (ex.: versão de servidores HTTP).
- **Suporte a IPv6**: Compatível com endereços IPv6.
- **Interface User-Friendly**: Argumentos via linha de comando e saída em tabela legível.

## Requisitos
- Python 3.x
- Módulos padrão: `socket`, `threading`, `argparse`, `queue`, `datetime`, `ipaddress`

## Instalação
1. Clone ou salve o script como `main.py`.
2. Certifique-se de ter permissões para executar escaneamentos (pode exigir privilégios de root para algumas portas).

## Uso
```bash
python3 main.py <host> [-s START_PORT] [-e END_PORT] [-p PROTOCOL]