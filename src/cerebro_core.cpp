// cerebro_core.cpp
// Lógica del "cerebro" - ahora con getVersion + evaluarServicio
// Compilado a libcerebro.so, cifrado con AES-256-GCM y subido a GitHub Releases.
// Descargado dinámicamente por CerebroBridge.kt.

#include <jni.h>
#include <string>
#include <vector>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <android/log.h>

#define TAG "CerebroCore"

// ============================================================
//  CAPA 3: STRING ENCRYPTION (XOR)
//  Todos los strings críticos están cifrados con XOR y se
//  descifran solo al momento de usarlos. Un análisis estático
//  con `strings` no mostrará nada legible.
// ============================================================

namespace ofus {

static const unsigned char X_KEY[8] = {0x37, 0xA1, 0x5C, 0x2E, 0x91, 0x4D, 0xB8, 0x73};

// Strings cifrados (se descifran al usar)
static unsigned char S_VERSION[]       = {0x41, 0x90, 0x72, 0x1E, 0xBF, 0x7B, 0x84, 0x0E}; // "v1.0.7"
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

// Descifra un buffer cifrado in-place y lo retorna como std::string
static std::string dec(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= X_KEY[i % 8];
    }
    return std::string(reinterpret_cast<char*>(data), len);
}

} // namespace ofus

// ============================================================
//  CAPA 1: ANTI-FRIDA / ANTI-DEBUGGER
//  Detecta herramientas de hooking y depuración.
//  Si comprometido, devuelve false (silencioso, sin avisar).
// ============================================================

namespace seguridad {

// Busca strings sospechosos en /proc/self/maps (módulos cargados en memoria)
static bool detectarModulosSospechosos() {
    std::ifstream f("/proc/self/maps");
    if (!f.is_open()) return false;
    std::string linea;
    while (std::getline(f, linea)) {
        // Patrones típicos de Frida, Xposed y Substrate
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

// Verifica si hay un debugger activo (TracerPid > 0 = debuggeado)
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

// Verifica puertos típicos de Frida server (27042 default, 27043 secondary)
static bool detectarPuertoFrida() {
    std::ifstream f("/proc/net/tcp");
    if (!f.is_open()) return false;
    std::string linea;
    while (std::getline(f, linea)) {
        // Puerto 27042 = 69A2 hex, Puerto 27043 = 69A3 hex (en little-endian)
        if (linea.find("69A2") != std::string::npos) return true;
        if (linea.find("69A3") != std::string::npos) return true;
    }
    return false;
}

// Función principal - combina todas las detecciones
static bool entornoComprometido() {
    if (detectarModulosSospechosos()) return true;
    if (detectarDebugger()) return true;
    if (detectarPuertoFrida()) return true;
    return false;
}

} // namespace seguridad

namespace cerebro {

// ============================================================
//  Estructuras de datos
// ============================================================

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

// ============================================================
//  Utilidades geométricas
// ============================================================

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

// Parsea un JSON MUY simple tipo [{"lat":1.0,"lng":2.0,"radio":500,"favorita":true},...]
// Solo lo necesario para extraer zonas favoritas / bloqueadas.
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

// ============================================================
//  Lógica principal de evaluación de un servicio
// ============================================================

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

    // 1. Descripción obligatoria
    if (!tieneDescripcion) {
        r.motivo = ofus::dec(ofus::S_SIN_DESC, sizeof(ofus::S_SIN_DESC));
        return r;
    }

    // 2. Rechazo de paradas múltiples
    if (rechazarParadas && tieneParadas) {
        r.motivo = ofus::dec(ofus::S_TIENE_PARADAS, sizeof(ofus::S_TIENE_PARADAS));
        return r;
    }

    // 3. Rango de precio
    if (precioMinimo > 0.0 && precio < precioMinimo) {
        r.motivo = ofus::dec(ofus::S_PRECIO_BAJO, sizeof(ofus::S_PRECIO_BAJO));
        return r;
    }
    if (precioMaximo > 0.0 && precio > precioMaximo) {
        r.motivo = ofus::dec(ofus::S_PRECIO_SOBRE, sizeof(ofus::S_PRECIO_SOBRE));
        return r;
    }

    // 4. Distancia de recogida
    if (distanciaMaxima > 0.0 && distanciaRecogida > distanciaMaxima) {
        r.motivo = ofus::dec(ofus::S_MUY_LEJOS, sizeof(ofus::S_MUY_LEJOS));
        return r;
    }

    // 5. Zonas favoritas / bloqueadas
    if (latDestino != 0.0 && lngDestino != 0.0) {
        std::vector<Zona> zonas = parsearZonasJson(zonasJson);
        for (const auto& z : zonas) {
            double d = distanciaMetros(z.lat, z.lng, latDestino, lngDestino);
            if (d <= z.radioMetros) {
                if (!z.esFavorita) {
                    r.motivo = ofus::dec(ofus::S_ZONA_BLOQ, sizeof(ofus::S_ZONA_BLOQ));
                    return r;
                }
                // Si es favorita, se acepta con bonus
                r.aceptado = true;
                r.motivo = ofus::dec(ofus::S_ZONA_FAV, sizeof(ofus::S_ZONA_FAV));
                r.distanciaDestino = d;
                return r;
            }
        }
    }

    // Aceptado por defecto
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

    // ==================================================
    //  CAPA 1: ANTI-FRIDA - Chequeo silencioso
    //  Si el entorno está comprometido (Frida, debugger,
    //  módulos sospechosos), devuelve "rechazado" sin
    //  ejecutar la lógica real. NO muestra nada.
    // ==================================================
    if (seguridad::entornoComprometido()) {
        return env->NewStringUTF(
            "{\"aceptado\":false,\"motivo\":\"rechazado\",\"distancia\":0.00}"
        );
    }

    // ==================================================
    //  CAPA 2: VALIDACIÓN DE FIRMA SHA-256
    //  Compara el SHA de la firma que Kotlin calculó
    //  contra el SHA esperado (guardado al primer arranque).
    //  Si NO se pasó SHA o es NULL → comprometido.
    //  Si difiere del esperado → APK re-firmada.
    // ==================================================
    if (shaFirmaActual == nullptr) {
        return env->NewStringUTF(
            "{\"aceptado\":false,\"motivo\":\"rechazado\",\"distancia\":0.00}"
        );
    }

    const char* shaChars = env->GetStringUTFChars(shaFirmaActual, nullptr);
    std::string shaStr = (shaChars != nullptr) ? shaChars : "";
    env->ReleaseStringUTFChars(shaFirmaActual, shaChars);

    // SHA esperado: 64 caracteres hexadecimales (256 bits)
    // Se establece al primer arranque desde Kotlin.
    static std::string shaEsperado = "";
    static bool shaInicializado = false;

    // Si es la primera vez, guardamos el SHA como referencia
    if (!shaInicializado && shaStr.length() == 64) {
        shaEsperado = shaStr;
        shaInicializado = true;
    }

    // Validar: SHA debe existir, tener 64 chars hex y coincidir
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
