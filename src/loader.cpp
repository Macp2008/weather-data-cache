#include <jni.h>
#include <string>
#include <vector>
#include <android/log.h>

#define TAG "CerebroLoader"

// Punto de entrada: la app Kotlin llamará a esta función
extern "C" JNIEXPORT jboolean JNICALL
Java_com_macbotin_indriverfilter_CerebroBridge_loadCerebro(
        JNIEnv *env,
        jobject /* this */,
        jstring url,
        jstring version) {

    const char *urlC = env->GetStringUTFChars(url, nullptr);
    const char *versionC = env->GetStringUTFChars(version, nullptr);

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "Cargando cerebro desde: %s (v%s)", urlC, versionC);

    // Por ahora: solo log. La lógica real viene en el Paso 4.
    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "Loader inicializado correctamente");

    env->ReleaseStringUTFChars(url, urlC);
    env->ReleaseStringUTFChars(version, versionC);

    return JNI_TRUE;
}
