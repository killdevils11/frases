# Validador y generador de frase MetaMask (BIP-39)

Este programa valida si una frase semilla es correcta para MetaMask según el estándar BIP-39 y también puede generar nuevas frases seguras:

- Verifica la cantidad de palabras (12/15/18/21/24).
- Comprueba que cada palabra exista en la wordlist oficial.
- Valida el checksum BIP-39.
- Genera frases nuevas usando entropía segura del sistema.
- Incluye un menú interactivo para validar o generar frases.
- Permite mostrar detalles de validación (entropía, checksum e índices BIP-39).

> Nota: No incluye ni soporta fuerza bruta ni búsqueda de fondos.

## Uso

Validar una frase:

```bash
python metamask_validator.py "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

Validar con detalles:

```bash
python metamask_validator.py --details "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

Generar una frase nueva:

```bash
python metamask_validator.py --generate 12
```

Abrir el menú interactivo:

```bash
python metamask_validator.py --menu
```

Si no pasas la frase como argumento, el programa la solicitará por consola.
