#!/usr/bin/env bash
# Builds the Cloak Burp extension jar.
#
# Requirements: JDK 17+ and the Montoya API jar. Put montoya-api-<version>.jar in this
# directory, or pass its path as the first argument. Download it from:
#   https://central.sonatype.com/artifact/net.portswigger.burp.extensions/montoya-api
set -euo pipefail
cd "$(dirname "$0")"

MONTOYA="${1:-$(ls montoya-api-*.jar 2>/dev/null | head -n1 || true)}"
if [[ -z "${MONTOYA}" || ! -f "${MONTOYA}" ]]; then
  echo "error: montoya-api jar not found." >&2
  echo "       place montoya-api-<version>.jar here, or run: ./build.sh /path/to/montoya-api.jar" >&2
  exit 1
fi

OUT="out"
JAR="cloak.jar"
rm -rf "${OUT}" "${JAR}"
mkdir -p "${OUT}"

echo "Compiling against ${MONTOYA} ..."
find src/main/java -name '*.java' > sources.txt
javac --release 17 -d "${OUT}" -cp "${MONTOYA}" @sources.txt
rm -f sources.txt

jar cf "${JAR}" -C "${OUT}" .
echo "Built ${JAR}"
echo "Load it in Burp: Extensions -> Installed -> Add -> Java -> ${JAR}"
