#!/usr/bin/env bash
# Convierte una COPIA de la plantilla en un proyecto nuevo.
#
#   scripts/new-project.sh <slug> <paquete.java> ["Nombre legible"]
#   ej.:  scripts/new-project.sh almacen-pos py.com.miempresa.almacen "Almacen POS"
#
# Hace: renombra el paquete Java y los artefactos, rellena SECURITY_DECISIONS.md, elimina los archivos exclusivos de la
# plantilla (ver .template/template-only-files.txt) y deja la version de la plantilla en .template/VERSION.
# Se ejecuta UNA sola vez, justo despues de crear el repositorio desde la plantilla.
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$(dirname "$(readlink -f "$0")")")"

slug="${1:-}"; pkg="${2:-}"; name="${3:-}"
[[ "$slug" =~ ^[a-z][a-z0-9-]{1,40}$ ]] || { echo "slug invalido (minusculas, digitos y guiones): '$slug'" >&2; exit 2; }
[[ "$pkg" =~ ^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$ ]] || { echo "paquete Java invalido (ej. py.com.miempresa.app): '$pkg'" >&2; exit 2; }
[ -n "$name" ] || name="$slug"
[ -d backend/src/main/java/com/example/app ] || { echo "Parece que ya se inicializo este proyecto (no existe com/example/app)." >&2; exit 1; }

group="${pkg%.*}"; leaf="${pkg##*.}"
today=$(date -u +%F)
pkgpath="${pkg//./\/}"

echo "Proyecto: $name  slug=$slug  paquete=$pkg"

# 1) Paquete Java
for scope in main test; do
  base="backend/src/$scope/java"
  [ -d "$base/com/example/app" ] || continue
  mkdir -p "$base/$pkgpath"
  cp -R "$base/com/example/app/." "$base/$pkgpath/"
  rm -rf "$base/com"
done
grep -rl --include='*.java' --include='*.xml' --include='*.yml' 'com\.example\.app' backend | xargs sed -i "s/com\.example\.app/$pkg/g"

# 2) Maven (groupId / artifactId / nombre)
perl -0pi -e "s#<groupId>com\.example</groupId>\s*<artifactId>app</artifactId>\s*<version>([^<]*)</version>\s*<name>app</name>#<groupId>$group</groupId>\n  <artifactId>$slug</artifactId>\n  <version>\$1</version>\n  <name>$slug</name>#" backend/pom.xml
sed -i "s/^    name: app$/    name: $slug/" backend/src/main/resources/application.yml

# 3) Frontend y compose
sed -i "s/\"name\": \"app-frontend\"/\"name\": \"$slug-frontend\"/" frontend/package.json
sed -i "s#<title>App</title>#<title>$name</title>#" frontend/index.html
sed -i "s/DB_NAME:-app/DB_NAME:-${slug//-/_}/g" docker-compose.yml
sed -i "s/^DB_NAME=app$/DB_NAME=${slug//-/_}/" .env.example
sed -i "s/\"App\"/\"$name\"/" backend/src/main/java/${pkgpath}/auth/MfaService.java
sed -i 's/context.add("app");/context.add("'"$slug"'");/' backend/src/main/java/${pkgpath}/auth/AccountService.java

# 4) Documentos del proyecto
sed -i "s/{{PROJECT_NAME}}/$name/g; s/{{DATE}}/$today/g; s/{{PACKAGE}}/$pkg/g" SECURITY_DECISIONS.md CLAUDE.md
if [ -f .template/README.project.md ]; then
  sed "s/{{PROJECT_NAME}}/$name/g; s/{{SLUG}}/$slug/g" .template/README.project.md > README.md
  rm .template/README.project.md
fi

# 5) Archivos exclusivos de la plantilla
while IFS= read -r f; do case "$f" in ''|\#*) continue ;; esac; rm -f "$f"; done < .template/template-only-files.txt
rm -f .template/template-only-files.txt

echo
echo "Listo. Pasos siguientes:"
echo "  1. cp .env.example .env  y complete los secretos (openssl rand -base64 24 / 32)."
echo "  2. docker compose up -d db  &&  (cd backend && mvn verify)  &&  (cd frontend && npm ci && npm test)"
echo "  3. Complete la Ficha del proyecto en SECURITY_DECISIONS.md y docs/privacy/INVENTARIO_DATOS.md."
echo "  4. Reemplace @OWNER en .github/CODEOWNERS y active en GitHub: Dependabot alerts, secret scanning, branch protection."
echo "  5. git add -A && git commit -m 'Inicializa proyecto desde la plantilla de seguridad'"
echo "  Actualizaciones futuras:  scripts/template-sync.sh --check"
