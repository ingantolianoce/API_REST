#!/usr/bin/env bash
# Sincroniza los archivos GESTIONADOS por la plantilla de seguridad (ver .template/managed-files.txt).
#
#   scripts/template-sync.sh --check            # solo informa diferencias (codigo de salida 1 si hay)
#   scripts/template-sync.sh                    # aplica la ultima version de la rama principal
#   scripts/template-sync.sh --ref v1.2.0       # aplica una version concreta (etiqueta o rama)
#
# Requiere: git, acceso de lectura al repositorio indicado en .template/UPSTREAM.
# NO toca el codigo (backend/frontend): los cambios de "Codigo base" se listan en el CHANGELOG de la plantilla
# y se aplican a mano (porque el paquete Java y el codigo del proyecto divergen).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

check_only=0; ref=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check) check_only=1 ;;
    --ref) ref="${2:?falta valor para --ref}"; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Argumento desconocido: $1" >&2; exit 2 ;;
  esac
  shift
done

upstream=$(tr -d '[:space:]' < .template/UPSTREAM)
local_v=$(tr -d '[:space:]' < .template/VERSION)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

echo "Plantilla: $upstream  (version local: $local_v)"
if [ -n "$ref" ]; then git clone --quiet --depth 1 --branch "$ref" "$upstream" "$tmp/t"
else git clone --quiet --depth 1 "$upstream" "$tmp/t"; fi
remote_v=$(tr -d '[:space:]' < "$tmp/t/.template/VERSION")
echo "Version de la plantilla: $remote_v"

# La lista de archivos gestionados la define la VERSION NUEVA de la plantilla (puede agregar archivos).
changed=0
while IFS= read -r f; do
  case "$f" in ''|\#*) continue ;; esac
  case "$f" in /*|*..*) echo "Ruta no permitida en managed-files: $f" >&2; exit 2 ;; esac
  src="$tmp/t/$f"
  [ -f "$src" ] || { echo "  (la plantilla ya no incluye $f; revise manualmente)"; continue; }
  if [ ! -f "$f" ] || ! cmp -s "$src" "$f"; then
    changed=1
    if [ -f "$f" ]; then echo "  ~ $f"; else echo "  + $f"; fi
    [ "$check_only" = 1 ] || { mkdir -p "$(dirname "$f")"; cp "$src" "$f"; }
  fi
done < "$tmp/t/.template/managed-files.txt"

if [ "$check_only" = 1 ]; then
  [ "$changed" = 0 ] && echo "Sin diferencias." || echo "Hay diferencias: ejecute scripts/template-sync.sh"
  exit "$changed"
fi

printf '%s\n' "$remote_v" > .template/VERSION
echo
if [ "$changed" = 0 ]; then echo "Archivos gestionados ya estaban al dia."; else echo "Archivos actualizados. Revise con: git diff"; fi
echo "Siguiente: lea CHANGELOG.md de la plantilla ($upstream/blob/main/CHANGELOG.md) entre $local_v y $remote_v"
echo "           y aplique a mano los cambios marcados como 'Codigo base'. Luego ejecute los tests y haga commit."
