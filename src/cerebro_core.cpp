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
    r.motivo = "desconocido";

    // 1. Descripción obligatoria
    if (!tieneDescripcion) {
        r.motivo = "sin_descripcion";
        return r;
    }

    // 2. Rechazo de paradas múltiples
    if (rechazarParadas && tieneParadas) {
        r.motivo = "tiene_paradas";
        return r;
    }

    // 3. Rango de precio
    if (precioMinimo > 0.0 && precio < precioMinimo) {
        r.motivo = "precio_bajo_minimo";
        return r;
    }
    if (precioMaximo > 0.0 && precio > precioMaximo) {
        r.motivo = "precio_sobre_maximo";
        return r;
    }

    // 4. Distancia de recogida
    if (distanciaMaxima > 0.0 && distanciaRecogida > distanciaMaxima) {
        r.motivo = "demasiado_lejos";
        return r;
    }

    // 5. Zonas favoritas / bloqueadas
    if (latDestino != 0.0 && lngDestino != 0.0) {
        std::vector<Zona> zonas = parsearZonasJson(zonasJson);
        for (const auto& z : zonas) {
            double d = distanciaMetros(z.lat, z.lng, latDestino, lngDestino);
            if (d <= z.radioMetros) {
                if (!z.esFavorita) {
                    r.motivo = "zona_bloqueada";
                    return r;
                }
                // Si es favorita, se acepta con bonus
                r.aceptado = true;
                r.motivo = "zona_favorita";
                r.distanciaDestino = d;
                return r;
            }
        }
    }

    // Aceptado por defecto
    r.aceptado = true;
    r.motivo = "ok";
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
    return env->NewStringUTF("v1.0.5");
}

JNIEXPORT jstring JNICALL
Java_com_macbotin_indriverfilter_indriverfilter_CerebroBridge_evaluarServicioNative(
    JNIEnv *env,
    jobject,
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
