#!/data/data/com.termux/files/usr/bin/bash
# build_and_encrypt.sh - Compila y cifra libcerebro.so
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ROOT_DIR="$(dirname "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)")"
KEY_FILE="$ROOT_DIR/keys/cerebro_aes.key"
BUILD_DIR="$ROOT_DIR/build"
OUTPUT_DIR="$ROOT_DIR/release"
LOG_DIR="$HOME/tmp"
SO_NAME="libcerebro.so"

mkdir -p "$LOG_DIR"

echo -e "${YELLOW}[*] Raíz del proyecto: $ROOT_DIR${NC}"

# 1. Verificar llave
[ -f "$KEY_FILE" ] || { echo -e "${RED}[!] Falta $KEY_FILE${NC}"; exit 1; }
KEY_HEX=$(tr -d '\n\r ' < "$KEY_FILE")
[ ${#KEY_HEX} -eq 64 ] || { echo -e "${RED}[!] Llave debe ser 64 chars hex (tiene ${#KEY_HEX})${NC}"; exit 1; }
echo -e "${GREEN}[OK] Llave AES-256 verificada (64 chars hex)${NC}"

# 2. Limpiar builds anteriores
rm -rf "$BUILD_DIR" "$OUTPUT_DIR"
mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"

# 3. Compilar con CMake
echo -e "${YELLOW}[*] Compilando $SO_NAME...${NC}"
cd "$BUILD_DIR"

echo "    Configurando con cmake..."
cmake "$ROOT_DIR" -DCMAKE_CXX_COMPILER=clang++ > "$LOG_DIR/cmake.log" 2>&1 || {
    echo -e "${RED}[!] CMake falló. Log:${NC}"
    cat "$LOG_DIR/cmake.log"
    exit 1
}

echo "    Compilando..."
make -j2 > "$LOG_DIR/make.log" 2>&1 || {
    echo -e "${RED}[!] Make falló. Log:${NC}"
    cat "$LOG_DIR/make.log"
    exit 1
}

[ -f "$SO_NAME" ] || { echo -e "${RED}[!] No se generó $SO_NAME${NC}"; ls -la; exit 1; }
SO_SIZE=$(stat -c%s "$SO_NAME" 2>/dev/null || stat -f%z "$SO_NAME")
echo -e "${GREEN}[OK] $SO_NAME compilado ($SO_SIZE bytes)${NC}"

# 4. Copiar a release
cp "$SO_NAME" "$OUTPUT_DIR/$SO_NAME"

# 5. Cifrar con AES-256-GCM
echo -e "${YELLOW}[*] Cifrando con AES-256-GCM...${NC}"
python "$ROOT_DIR/tools/encrypt_so.py" \
    "$OUTPUT_DIR/$SO_NAME" \
    "$OUTPUT_DIR/$SO_NAME.enc" \
    "$KEY_HEX"

ENC_SIZE=$(stat -c%s "$OUTPUT_DIR/$SO_NAME.enc" 2>/dev/null || stat -f%z "$OUTPUT_DIR/$SO_NAME.enc")

# 6. Metadata
VERSION="1.0.0-$(date +%Y%m%d%H%M%S)"
cat > "$OUTPUT_DIR/METADATA.json" << EOF
{
  "version": "$VERSION",
  "so_size": $SO_SIZE,
  "enc_size": $ENC_SIZE,
  "algorithm": "AES-256-GCM",
  "build_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  COMPILACIÓN + CIFRADO EXITOSOS${NC}"
echo -e "${GREEN}============================================${NC}"
echo "Archivos en: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"
