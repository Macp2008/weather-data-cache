// cerebro_core.cpp
// Cerebro nativo v1.1.0 - Con CAPA 5 (License Validation)
//
// Capas implementadas:
//   CAPA 1: Anti-Frida / Anti-Debugger
//   CAPA 2: SHA-256 signature validation (fail-closed)
//   CAPA 3: String encryption (XOR)
//   CAPA 4: Compiler flags (-O3, strip, hidden visibility)
//   CAPA 5: HMAC-SHA256 license validation (kill switch remoto)
//
// Compilado a libcerebro.so, cifrado con AES-256-GCM y
// subido a GitHub Releases. Descargado dinámicamente por
// CerebroBridge.kt.

#include <jni.h>
#include <string>
#include <vector>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <ctime>
#include <android/log.h>

#define TAG "CerebroCore"

// ============================================================
//  CAPA 3: STRING ENCRYPTION (XOR)
// ============================================================

namespace ofus {

static const unsigned char X_KEY[8] = {0x37, 0xA1, 0x5C, 0x2E, 0x91, 0x4D, 0xB8, 0x73};

// Strings cifrados (se descifran al usar)
static unsigned char S_VERSION[]       = {0x41, 0x90, 0x72, 0x1E, 0xBF, 0x7B, 0x84, 0x0E}; // "v1.1.0"
static unsigned char S_RECHAZADO[]     = {0x45, 0xC4, 0x3F, 0x46, 0xF0, 0x37, 0xD9, 0x17, 0x58};
static unsigned char S_OK[]            = {0x58, 0xCA};
static unsigned char S_DESCONOCIDO[]   = {0x53, 0xC4, 0x2F, 0x4D, 0xFE, 0x23, 0xD7, 0x10, 0x5E, 0xC5, 0x33};
static unsigned char S_SIN_DESC[]      = {0x44, 0xC8, 0x32, 0x71, 0xF5, 0x28, 0xCB, 0x10, 0x45, 0xC8, 0x2C, 0x4D, 0xF8, 0x22, 0xD6};
static unsigned char S_TIENE_PARADAS[] = {0x43, 0xC8, 0x39, 0x40, 0xF4, 0x12, 0xC8, 0x12, 0x45, 0xC0, 0x38, 0x4F, 0xE2};
static unsigned char S_PRECIO_BAJO[]   = {0x47, 0xD3, 0x39, 0x4D, 0xF8, 0x22, 0xE7, 0x11, 0x56, 0xCB, 0x33, 0x71, 0xFC, 0x24, 0xD6, 0x1A, 0x5A, 0xCE};
static unsigned char S_PRECIO_SOBRE[]  = {0x47, 0xD3, 0x39, 0x4D, 0xF8, 0x22, 0xE7, 0x00, 0x58, 0xC3, 0x2E, 0x4B, 0xCE, 0x20, 0xD9, 0x0B, 0x5E, 0xCC, 0x33};
static unsigned char S_MUY_LEJOS[]     = {0x53, 0xC4, 0x31, 0x4F, 0xE2, 0x24, 0xD9, 0x17, 0x58, 0xFE, 0x30, 0x4B, 0xFB, 0x22, 0xCB};
static unsigned char S_ZONA_BLOQ[]     = {0x4D, 0xCE, 0x32, 0x4F, 0xCE, 0x2F, 0xD4, 0x1C, 0x46, 0xD4, 0x39, 0x4F, 0xF5, 0x2C};
static unsigned char S_ZONA_FAV[]      = {0x4D, 0xCE, 0x32, 0x4F, 0xCE, 0x2B, 0xD9, 0x05, 0x58, 0xD3, 0x35, 0x5A, 0xF0};
static unsigned char S_FAVORITA[]      = {0x51, 0xC0, 0x2A, 0x41, 0xE3, 0x24, 0xCC, 0x12};
static unsigned char S_LAT[]           = {0x5B, 0xC0, 0x28};
static unsigned char S_LNG[]           = {0x5B, 0xCF, 0x3B};
static unsigned char S_RADIO[]         = {0x45, 0xC0, 0x38, 0x47, 0xFE};

// CAPA 5 - Strings específicos de licencia
static unsigned char S_LIC_VALIDA[]    = {0x53, 0xCF, 0x3B, 0x4F, 0xCE, 0x2D, 0x5C, 0xCE}; // "lic_valida" (placeholder, real: "valida")
static unsigned char S_LIC_INVALIDA[]  = {0x53, 0xCF, 0x3B, 0x4F, 0xCE, 0x2F, 0x5C, 0xC5, 0x39}; // "lic_invalida"

// Descifra un buffer cifrado in-place y lo retorna como std::string
static std::string dec(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= X_KEY[i % 8];
    }
    return std::string(reinterpret_cast<char*>(data), len);
}

} // namespace ofus

// ============================================================
//  CAPA 5: SHA-256 + HMAC-SHA256 (implementación propia)
//  No dependemos de OpenSSL porque no está linkeado al .so
// ============================================================

namespace crypto {

// Constantes K de SHA-256 (RFC 6234)
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256Bloque(uint32_t estado[8], const uint8_t bloque[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t(bloque[i*4])   << 24) |
               (uint32_t(bloque[i*4+1]) << 16) |
               (uint32_t(bloque[i*4+2]) <<  8) |
               (uint32_t(bloque[i*4+3]));
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a = estado[0], b = estado[1], c = estado[2], d = estado[3];
    uint32_t e = estado[4], f = estado[5], g = estado[6], h = estado[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    estado[0] += a; estado[1] += b; estado[2] += c; estado[3] += d;
    estado[4] += e; estado[5] += f; estado[6] += g; estado[7] += h;
}

static void sha256(const uint8_t* datos, size_t len, uint8_t out[32]) {
    uint32_t estado[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Procesar bloques completos
    size_t bloquesCompletos = len / 64;
    for (size_t i = 0; i < bloquesCompletos; i++) {
        sha256Bloque(estado, datos + i * 64);
    }

    // Padding final
    uint8_t pad[128] = {0};
    size_t rem = len % 64;
    memcpy(pad, datos + bloquesCompletos * 64, rem);
    pad[rem] = 0x80;

    size_t padLen = (rem < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) {
        pad[padLen - 8 + i] = (uint8_t)(bits >> (56 - i*8));
    }

    for (size_t i = 0; i < padLen / 64; i++) {
        sha256Bloque(estado, pad + i * 64);
    }

    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(estado[i] >> 24);
        out[i*4+1] = (uint8_t)(estado[i] >> 16);
        out[i*4+2] = (uint8_t)(estado[i] >>  8);
        out[i*4+3] = (uint8_t)(estado[i]);
    }
}

// HMAC-SHA256: H((K' xor opad) || H((K' xor ipad) || mensaje))
static void hmacSha256(const uint8_t* key, size_t keyLen,
                       const uint8_t* msg, size_t msgLen,
                       uint8_t out[32]) {
    uint8_t kBloque[64] = {0};
    if (keyLen > 64) {
        sha256(key, keyLen, kBloque);
    } else {
        memcpy(kBloque, key, keyLen);
    }

    uint8_t iKey[64], oKey[64];
    for (int i = 0; i < 64; i++) {
        iKey[i] = kBloque[i] ^ 0x36;
        oKey[i] = kBloque[i] ^ 0x5C;
    }

    // inner = SHA256(iKey || msg)
    uint8_t innerHash[32];
    uint8_t* innerBuf = new uint8_t[64 + msgLen];
    memcpy(innerBuf, iKey, 64);
    if (msgLen > 0) memcpy(innerBuf + 64, msg, msgLen);
    sha256(innerBuf, 64 + msgLen, innerHash);
    delete[] innerBuf;

    // out = SHA256(oKey || innerHash)
    uint8_t outerBuf[96];
    memcpy(outerBuf, oKey, 64);
    memcpy(outerBuf + 64, innerHash, 32);
    sha256(outerBuf, 96, out);
}

static std::string aHex(const uint8_t* datos, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        s.push_back(hex[(datos[i] >> 4) & 0xF]);
        s.push_back(hex[(datos[i] & 0xF)]);
    }
    return s;
}

} // namespace crypto

// ============================================================
//  CAPA 1: ANTI-FRIDA / ANTI-DEBUGGER
// ============================================================

namespace seguridad {

static bool detectarModulosSospechosos() {
    std::ifstream f("/proc/self/maps");
    if (!f.is_open()) return false;
    std::string linea;
    while (std::getline(f, linea)) {
        if (linea.find("frida") != std::string::npos) return true;
        if (linea.find("gadget") != std::string::npos) return true;
        if (linea.find("xposed") != std::string::npos) return true;
        if (linea.find("substrate") != std::string::npos) return true;
        if (linea.find("libsubstrate") != std::string::npos) return true;
        if (linea.find("libhook") != std::string::npos) return true;
        if (linea.find("magisk") != std::string::npos) return true;
    }
    return false;
}

static bool detectarDebugger() {
    std::ifstream f("/proc/self/status");
    if (!f.is_open()) return false;
    std::string linea;
    while (std::getline(f, linea)) {
        if (linea.find("TracerPid:") != std::string::npos) {
            size_t pos = linea.find(':');
            if (pos != std::string::npos) {
                int pid = std::atoi(linea.c_str() + pos + 1);
                return pid != 0;
            }
        }
    }
    return false;
}

static bool detectarPuertoFrida() {
    std::ifstream f("/proc/net/tcp");
    if (!f.is_open()) return false;
    std::string linea;
    while (std::getline(f, linea)) {
        if (linea.find("69A2") != std::string::npos) return true;
        if (linea.find("69A3") != std::string::npos) return true;
    }
    return false;
}

static bool entornoComprometido() {
    if (detectarModulosSospechosos()) return true;
    if (detectarDebugger()) return true;
    if (detectarPuertoFrida()) return true;
    return false;
}

} // namespace seguridad

// ============================================================
//  CAPA 5: VALIDACIÓN DE LICENCIA CON HMAC-SHA256
// ============================================================

namespace licencia {

// ============================================================
// CHUNKS DE LLAVE HMAC - Generados con sign_license.py
// ============================================================
static const char* KEY_CHUNKS_HMAC[] = {
    "bb4a8c1c",
    "80cf7ae0",
    "34fba024",
    "14b10b70",
    "c26fed10",
    "32ad70a2",
    "7402c6fc",
    "a248fb7c"
};

static const uint8_t KEY_MASK[8] = {0x37, 0xA1, 0x5C, 0x2E, 0x91, 0x4D, 0xB8, 0x73};

// Reconstruye los 32 bytes de la llave HMAC
static bool obtenerLlaveHmac(uint8_t out[32]) {
    std::string hexCompleto;
    for (int i = 0; i < 8; i++) {
        const char* chunk = KEY_CHUNKS_HMAC[i];
        if (chunk[0] == '_' || strlen(chunk) != 8) return false;
        hexCompleto += chunk;
    }
    if (hexCompleto.length() != 64) return false;

    for (int i = 0; i < 32; i++) {
        int byte = 0;
        bool ok = true;
        for (int j = 0; j < 2; j++) {
            char c = hexCompleto[i * 2 + j];
            int v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else { ok = false; break; }
            byte = (byte << 4) | v;
        }
        if (!ok) return false;
        out[i] = (uint8_t)(byte ^ KEY_MASK[i % 8]);
    }
    return true;
}

// Cache de licencia
static bool    licValida       = false;
static int64_t licExpira       = 0;
static int64_t licUltimaCheck  = 0;
static std::string licMotivoRechazo = "no_inicializado";

// Helpers para parsear JSON muy simple (sin regex)
static bool jsonContiene(const std::string& json, const std::string& patron) {
    return json.find(patron) != std::string::npos;
}

static std::string jsonExtraerString(const std::string& json, const std::string& clave) {
    std::string patron = "\"" + clave + "\":\"";
    size_t pos = json.find(patron);
    if (pos == std::string::npos) return "";
    pos += patron.length();
    size_t fin = json.find('"', pos);
    if (fin == std::string::npos) return "";
    return json.substr(pos, fin - pos);
}

static int64_t jsonExtraerInt(const std::string& json, const std::string& clave) {
    std::string patron = "\"" + clave + "\":";
    size_t pos = json.find(patron);
    if (pos == std::string::npos) return -1;
    pos += patron.length();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    return (int64_t)std::atoll(json.c_str() + pos);
}

// Verifica una respuesta JSON firmada con HMAC
static bool verificarLicenciaJson(const std::string& jsonStr) {
    uint8_t llave[32];
    if (!obtenerLlaveHmac(llave)) {
        licMotivoRechazo = "key_no_configurada";
        return false;
    }

    // Extraer campos del JSON
    bool valid = jsonContiene(jsonStr, "\"valid\":true");
    int64_t expires = jsonExtraerInt(jsonStr, "expires");
    std::string nonce = jsonExtraerString(jsonStr, "nonce");
    std::string sig = jsonExtraerString(jsonStr, "sig");

    if (nonce.empty() || sig.length() != 64 || expires < 0) {
        licMotivoRechazo = "json_invalido";
        return false;
    }

    // Recalcular HMAC: "{valid_bit}|{expires}|{nonce}"
    int valBit = valid ? 1 : 0;
    std::string mensaje = std::to_string(valBit) + "|" +
                          std::to_string(expires) + "|" + nonce;

    uint8_t esperado[32];
    crypto::hmacSha256(llave, 32,
                       (const uint8_t*)mensaje.c_str(), mensaje.size(),
                       esperado);
    std::string esperadoHex = crypto::aHex(esperado, 32);

    // Comparación constant-time
    if (esperadoHex.length() != sig.length()) {
        licMotivoRechazo = "firma_invalida";
        return false;
    }
    int diff = 0;
    for (size_t i = 0; i < sig.length(); i++) {
        diff |= (unsigned char)(esperadoHex[i] ^ sig[i]);
    }
    if (diff != 0) {
        licMotivoRechazo = "firma_invalida";
        return false;
    }

    // Firma válida, ahora validar campos
    if (!valid) {
        licMotivoRechazo = "revocada";
        licValida = false;
        return false;
    }

    int64_t ahora = (int64_t)time(nullptr);
    if (expires <= ahora) {
        licMotivoRechazo = "expirada";
        licValida = false;
        return false;
    }

    licValida = true;
    licExpira = expires;
    licUltimaCheck = ahora;
    licMotivoRechazo = "ok";
    return true;
}

static bool licenciaVigente() {
    if (!licValida) return false;
    int64_t ahora = (int64_t)time(nullptr);
    if (ahora >= licExpira) {
        licValida = false;
        licMotivoRechazo = "expirada_en_runtime";
        return false;
    }
    return true;
}

} // namespace licencia

// ============================================================
//  Lógica de cerebro (núcleo del filtro)
// ============================================================

namespace cerebro {

struct Zona {
    std::string nombre;
    double lat;
    double lng;
    double radioMetros;
    bool esFavorita;
};

struct Resultado {
    bool aceptado;
    std::string motivo;
    double distanciaDestino;
};

static double distanciaMetros(double lat1, double lng1,
                              double lat2, double lng2) {
    const double R = 6371000.0;
    double dLat = (lat2 - lat1) * M_PI / 180.0;
    double dLng = (lng2 - lng1) * M_PI / 180.0;
    double a = std::sin(dLat / 2) * std::sin(dLat / 2) +
               std::cos(lat1 * M_PI / 180.0) * std::cos(lat2 * M_PI / 180.0) *
               std::sin(dLng / 2) * std::sin(dLng / 2);
    double c = 2 * std::atan2(std::sqrt(a), std::sqrt(1 - a));
    return R * c;
}

static std::vector<Zona> parsearZonasJson(const std::string& json) {
    std::vector<Zona> zonas;
    if (json.empty() || json == "[]" || json == "null") return zonas;

    size_t pos = 0;
    while ((pos = json.find('{', pos)) != std::string::npos) {
        Zona z;
        z.esFavorita = false;
        z.radioMetros = 500.0;

        auto findNum = [&](const std::string& key, double& out) {
            size_t k = json.find("\"" + key + "\"", pos);
            if (k == std::string::npos) return false;
            size_t colon = json.find(':', k);
            if (colon == std::string::npos) return false;
            size_t start = colon + 1;
            while (start < json.size() && (json[start] == ' ' || json[start] == '\t')) start++;
            out = std::atof(json.c_str() + start);
            return true;
        };

        findNum("lat", z.lat);
        findNum("lng", z.lng);
        findNum("radio", z.radioMetros);

        size_t favPos = json.find("\"favorita\"", pos);
        if (favPos != std::string::npos && favPos < json.find('}', pos)) {
            size_t colon = json.find(':', favPos);
            std::string val = json.substr(colon + 1, 10);
            z.esFavorita = (val.find("true") != std::string::npos);
        }

        zonas.push_back(z);
        pos = json.find('}', pos);
        if (pos == std::string::npos) break;
        pos++;
    }
    return zonas;
}

static Resultado evaluarServicio(
    double precio,
    double distanciaRecogida,
    bool tieneDescripcion,
    bool tieneParadas,
    double latDestino,
    double lngDestino,
    const std::string& zonasJson,
    double precioMinimo,
    double precioMaximo,
    double distanciaMaxima,
    bool rechazarParadas
) {
    Resultado r;
    r.aceptado = false;
    r.motivo = ofus::dec(ofus::S_DESCONOCIDO, sizeof(ofus::S_DESCONOCIDO));

    if (!tieneDescripcion) {
        r.motivo = ofus::dec(ofus::S_SIN_DESC, sizeof(ofus::S_SIN_DESC));
        return r;
    }
    if (rechazarParadas && tieneParadas) {
        r.motivo = ofus::dec(ofus::S_TIENE_PARADAS, sizeof(ofus::S_TIENE_PARADAS));
        return r;
    }
    if (precioMinimo > 0.0 && precio < precioMinimo) {
        r.motivo = ofus::dec(ofus::S_PRECIO_BAJO, sizeof(ofus::S_PRECIO_BAJO));
        return r;
    }
    if (precioMaximo > 0.0 && precio > precioMaximo) {
        r.motivo = ofus::dec(ofus::S_PRECIO_SOBRE, sizeof(ofus::S_PRECIO_SOBRE));
        return r;
    }
    if (distanciaMaxima > 0.0 && distanciaRecogida > distanciaMaxima) {
        r.motivo = ofus::dec(ofus::S_MUY_LEJOS, sizeof(ofus::S_MUY_LEJOS));
        return r;
    }
    if (latDestino != 0.0 && lngDestino != 0.0) {
        std::vector<Zona> zonas = parsearZonasJson(zonasJson);
        for (const auto& z : zonas) {
            double d = distanciaMetros(z.lat, z.lng, latDestino, lngDestino);
            if (d <= z.radioMetros) {
                if (!z.esFavorita) {
                    r.motivo = ofus::dec(ofus::S_ZONA_BLOQ, sizeof(ofus::S_ZONA_BLOQ));
                    return r;
                }
                r.aceptado = true;
                r.motivo = ofus::dec(ofus::S_ZONA_FAV, sizeof(ofus::S_ZONA_FAV));
                r.distanciaDestino = d;
                return r;
            }
        }
    }

    r.aceptado = true;
    r.motivo = ofus::dec(ofus::S_OK, sizeof(ofus::S_OK));
    r.distanciaDestino = 0.0;
    return r;
}

} // namespace cerebro

// ============================================================
//  JNI EXPORTS
// ============================================================

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_macbotin_indriverfilter_indriverfilter_CerebroBridge_getVersion(JNIEnv *env, jobject) {
    return env->NewStringUTF(ofus::dec(ofus::S_VERSION, sizeof(ofus::S_VERSION)).c_str());
}

// CAPA 5: Valida la licencia descargada de Firebase.
JNIEXPORT jstring JNICALL
Java_com_macbotin_indriverfilter_indriverfilter_CerebroBridge_validarLicenciaNative(
    JNIEnv *env,
    jobject,
    jstring licenseJson
) {
    using namespace licencia;

    if (licenseJson == nullptr) {
        licMotivoRechazo = "json_null";
        return env->NewStringUTF("invalida");
    }

    const char* chars = env->GetStringUTFChars(licenseJson, nullptr);
    std::string jsonStr = (chars != nullptr) ? chars : "";
    env->ReleaseStringUTFChars(licenseJson, chars);

    bool ok = verificarLicenciaJson(jsonStr);
    return env->NewStringUTF(ok ? "valida" : "invalida");
}

// CAPA 5: Para diagnóstico
JNIEXPORT jstring JNICALL
Java_com_macbotin_indriverfilter_indriverfilter_CerebroBridge_motivoLicenciaNative(
    JNIEnv *env,
    jobject
) {
    return env->NewStringUTF(licencia::licMotivoRechazo.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_macbotin_indriverfilter_indriverfilter_CerebroBridge_evaluarServicioNative(
    JNIEnv *env,
    jobject,
    jstring shaFirmaActual,
    jdouble precio,
    jdouble distanciaRecogida,
    jboolean tieneDescripcion,
    jboolean tieneParadas,
    jdouble latDestino,
    jdouble lngDestino,
    jstring zonasJson,
    jdouble precioMinimo,
    jdouble precioMaximo,
    jdouble distanciaMaxima,
    jboolean rechazarParadas
) {
    using namespace cerebro;

    // CAPA 5: VERIFICAR LICENCIA REMOTA
    if (!licencia::licenciaVigente()) {
        return env->NewStringUTF(
            "{\"aceptado\":false,\"motivo\":\"licencia_invalida\",\"distancia\":0.00}"
        );
    }

    // CAPA 1: ANTI-FRIDA
    if (seguridad::entornoComprometido()) {
        return env->NewStringUTF(
            "{\"aceptado\":false,\"motivo\":\"rechazado\",\"distancia\":0.00}"
        );
    }

    // CAPA 2: VALIDACIÓN DE FIRMA SHA-256 DEL APK
    if (shaFirmaActual == nullptr) {
        return env->NewStringUTF(
            "{\"aceptado\":false,\"motivo\":\"rechazado\",\"distancia\":0.00}"
        );
    }

    const char* shaChars = env->GetStringUTFChars(shaFirmaActual, nullptr);
    std::string shaStr = (shaChars != nullptr) ? shaChars : "";
    env->ReleaseStringUTFChars(shaFirmaActual, shaChars);

    static std::string shaEsperado = "";
    static bool shaInicializado = false;

    if (!shaInicializado && shaStr.length() == 64) {
        shaEsperado = shaStr;
        shaInicializado = true;
    }

    if (shaEsperado.empty() || shaStr.length() != 64 || shaStr != shaEsperado) {
        return env->NewStringUTF(
            "{\"aceptado\":false,\"motivo\":\"rechazado\",\"distancia\":0.00}"
        );
    }

    const char* zonasChars = env->GetStringUTFChars(zonasJson, nullptr);
    std::string zonasStr = (zonasChars != nullptr) ? zonasChars : "[]";
    env->ReleaseStringUTFChars(zonasJson, zonasChars);

    Resultado r = evaluarServicio(
        (double)precio,
        (double)distanciaRecogida,
        (bool)tieneDescripcion,
        (bool)tieneParadas,
        (double)latDestino,
        (double)lngDestino,
        zonasStr,
        (double)precioMinimo,
        (double)precioMaximo,
        (double)distanciaMaxima,
        (bool)rechazarParadas
    );

    char buffer[512];
    std::snprintf(buffer, sizeof(buffer),
        "{\"aceptado\":%s,\"motivo\":\"%s\",\"distancia\":%.2f}",
        r.aceptado ? "true" : "false",
        r.motivo.c_str(),
        r.distanciaDestino
    );

    return env->NewStringUTF(buffer);
}

} // extern "C"
