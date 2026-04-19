
```markdown
![AXIS Logo](axis-logo.png)

<div align="center">

# **AXIS**  
**by Fracta**  
**MFSU Vault v3.0**

**Criptografía inspirada en la geometría del vacío cuántico**

</div>

---

### Badges

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status: Experimental](https://img.shields.io/badge/Status-Experimental-orange?style=flat-square)
![MFSU + TEG](https://img.shields.io/badge/Inspired_by-TEG_%2B_MFSU-8B00FF?style=flat-square)

---

### ¿Qué es AXIS?

**AXIS** es un vault criptográfico experimental que genera claves y patrones de confusión usando dinámicas fractales reales derivadas del **Modelo Fractal Estocástico Unificado (MFSU)** y del axioma tetraédrico de **Tetrahedral Emergent Gravity (TEG)**.

En lugar de usar solo funciones hash tradicionales, AXIS simula un pequeño sistema físico inspirado en la estructura más eficiente que parece elegir el vacío cuántico: coordinación tetraédrica, dimensión efectiva \(D_{\rm eff} = \ln 8\) y codimensión holográfica \(\delta \approx 0.921\).

El resultado es un **KDF memory-hard** con comportamiento fractal auto-similar, pensado para ser conceptualmente distinto y resistente.

---
## 🧪 El Algoritmo (MFSU)
Nuestra tecnología utiliza una semilla fractal que evoluciona con el tiempo y el ruido del sistema, haciendo que la clave de encriptación sea prácticamente imposible de predecir mediante métodos convencionales.

### Características principales

- Dinámica MFSU: Laplaciano fraccional + ruido con exponente de Hurst del CMB
- KDF memory-hard con scratchpad de 8 MB y acceso fractal impredecible
- Whitening con SHA3-256 + MAC para verificar integridad
- Normalización anti-timing-attack
- Formato de archivo `.fracta` con metadata clara
- Interfaz web fácil con Streamlit y modo CLI

---

### Cómo probarlo (muy fácil)

#### 1. Interfaz web (recomendada)

```bash
pip install streamlit numpy scipy
streamlit run fracts_vault.py
```

#### 2. Uso desde terminal

```bash
python fracts_vault.py --help
```

**Ejemplos:**
```bash
# Encriptar
python fracts_vault.py --encrypt miarchivo.pdf --password MiContraseñaSegura123

# Desencriptar
python fracts_vault.py --decrypt miarchivo.pdf.fracta --password MiContraseñaSegura123
```

---

### ⚠️ Advertencia importante

Este es un **proyecto experimental y de investigación**.  
No ha sido auditado formalmente por criptógrafos profesionales.  
**No lo uses para proteger información crítica o valiosa** hasta que tenga una revisión de seguridad independiente.

---

### Filosofía

AXIS nace de la idea de que la geometría más eficiente del universo para almacenar y proteger información es la misma que el vacío cuántico parece elegir según TEG.

No es solo otro algoritmo de encriptación. Es un intento de llevar principios físicos profundos (entropía holográfica y fractalidad auto-similar) al mundo de la criptografía práctica.

---

### Licencia

MIT License — puedes usar, modificar y distribuir libremente.

---

### Autor

**Miguel Ángel Franco León**  
Creador de **Tetrahedral Emergent Gravity (TEG)** y **MFSU**

- Paper completo: [Zenodo](https://zenodo.org/records/19479542)
- GitHub: [Fracta-Axis](https://github.com/Fracta-Axis)


