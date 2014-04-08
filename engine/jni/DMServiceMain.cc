// don't strip logging from release builds
#define LOG_NDEBUG 0

#include <android_runtime/AndroidRuntime.h>
#include "utils/Log.h"
#include "DMServiceMain.h"
#include "dmt.hpp"
#include "DMTreeManager.h"

static jobject g_sessionObj;
int g_cancelSession;

//#define LOGV printf
//#define LOGD printf


#define SET_RET_STATUS_BUF \
        jResult = jenv->NewByteArray(5); char szResult[5]; memset(szResult, 0, 5); \
        sprintf(szResult, "%4d", ret_status); \
        jenv->SetByteArrayRegion(jResult, 0, 5, (const jbyte*)szResult)

static void Dump( const char* buf, int size, boolean isBinary )
{
  if (!isBinary) {
    // just print the string
    char* szBuf = new char [size+1];

    memcpy(szBuf, buf, size);
    szBuf[size] = 0;
     
    printf("The test Script error text:\n\n%s\n\n", szBuf);
  } else {
    int nOffset = 0;
 
    while (size > 0) {
      int nLine = size > 16 ? 16 : size;
 
      char s[250];
      int pos = 0;
 
      pos += sprintf( s+pos, "%04x:", nOffset );
 
      for (int i = 0; i < nLine; i++) {
        pos += sprintf( s+pos, " %02x", (unsigned int)((unsigned char) buf[i]) );
      }
      for (int i = nLine; i < 16; i++) {
        pos += sprintf( s+pos, "   " );
      }
 
      pos += sprintf( s+pos, "  " );
      for ( int i = 0; i < nLine; i++ ){
        pos += sprintf( s+pos, "%c", (buf[i] > 31 ? buf[i] : '.') );
      }
 
      printf( "%s\n", s );
      buf += nLine;
      size -= nLine;
      nOffset += nLine;
    }
  }
}


JNIEXPORT jint
initialize(JNIEnv* env, jobject jobj)
{
  LOGD("native initialize");
  if (!DmtTreeFactory::Initialize()) {
    LOGE("Failed to initialize DM\n");
    return (jint)SYNCML_DM_FAIL;
  }

  return (jint)SYNCML_DM_SUCCESS;
}

JNIEXPORT jint
destroy(JNIEnv* env, jobject jobj)
{
  LOGD("Enter destroy");
  if (DmtTreeFactory::Uninitialize() != SYNCML_DM_SUCCESS) {
    LOGE("Failed to uninitialize DM\n");
    return (jint)SYNCML_DM_FAIL;
  }

  LOGD("Leave destroy");
  return SYNCML_DM_SUCCESS;
}

JNIEXPORT jint
parsePkg0(JNIEnv* env, jclass jclz, jbyteArray jPkg0, jobject jNotification)
{
    LOGD("Enter parsePkg0");
    jclass notifClass = env->GetObjectClass(jNotification);

    if (jPkg0 == NULL) {
        return SYNCML_DM_FAIL;
    }

    jbyte* pkg0Buf = env->GetByteArrayElements(jPkg0, NULL);
    jsize pkg0Len = env->GetArrayLength(jPkg0);

    DmtNotification notif;
    DmtPrincipal p("localhost");
    SYNCML_DM_RET_STATUS_T ret = DmtTreeFactory::ProcessNotification(p, (UINT8*)pkg0Buf, (INT32)pkg0Len, notif);

    jmethodID jSetServerID = env->GetMethodID( notifClass, "setServerID", "(Ljava/lang/String;)V");
    jstring jServerID = env->NewStringUTF(notif.getServerID());
    env->CallVoidMethod(jNotification, jSetServerID, jServerID);

    jmethodID jSetSessionID = env->GetMethodID( notifClass, "setSessionID", "(I)V");
    env->CallVoidMethod(jNotification, jSetSessionID, (jint)notif.getSessionID());

    jmethodID jSetUIMode = env->GetMethodID( notifClass, "setUIMode", "(I)V");
    env->CallVoidMethod(jNotification, jSetUIMode, (jint)notif.getUIMode());

    jmethodID jSetInitiator = env->GetMethodID( notifClass, "setInitiator", "(I)V");
    env->CallVoidMethod(jNotification, jSetInitiator, (jint)notif.getInitiator());

    jmethodID jSetAuthFlag = env->GetMethodID( notifClass, "setAuthFlag", "(I)V");
    env->CallVoidMethod(jNotification, jSetAuthFlag, (jint)notif.getAuthFlag());

    env->ReleaseByteArrayElements(jPkg0, pkg0Buf, 0);

    LOGD("Leave parsePkg0, ret: %d", ret);
    return ret;
}


JNIEXPORT jint JNICALL startFotaClientSession
  (JNIEnv *jenv, jclass jclz, jstring jServerId, jstring jAlertStr, jobject jdmobj)
{
    LOGV("In native startFotaClientSession\n");

    SYNCML_DM_RET_STATUS_T ret_status = SYNCML_DM_FAIL;
    DMString serverID;

    g_sessionObj = jdmobj;

    const char* szDmServerId = jenv->GetStringUTFChars(jServerId, NULL);
    const char* szDmAlertStr = NULL;
    if (jAlertStr != NULL) {
        szDmAlertStr = jenv->GetStringUTFChars(jAlertStr, NULL);
    }

    DmtPrincipal principal( szDmServerId );

    DMString alertURI = "./DevDetail/Ext/SystemUpdate";
    DmtFirmAlert alert(alertURI, NULL, szDmAlertStr, "chr", NULL, NULL);
    DmtSessionProp prop(alert, true);

    g_cancelSession = 0;

    ret_status = DmtTreeFactory::StartServerSession(principal, prop);

    if (jAlertStr!=NULL) {
        jenv->ReleaseStringUTFChars(jAlertStr, szDmAlertStr);
    }

    g_sessionObj = NULL;
    if (ret_status == SYNCML_DM_SUCCESS) {
        LOGV("Native startFotaClientSession return successfully\n");
        return SYNCML_DM_SUCCESS;
    } else {
        LOGE("Native startFotaClientSession return error %d\n", ret_status);
        return ret_status;
    }
}

JNIEXPORT jint JNICALL startClientSession
  (JNIEnv *jenv, jclass jclz, jstring jServerId, jobject jdmobj)
{
    LOGV("In native startClientSession\n");

    SYNCML_DM_RET_STATUS_T ret_status = SYNCML_DM_FAIL;
    DMString serverID;

    g_sessionObj = jdmobj;
    const char* szDmServerId = jenv->GetStringUTFChars(jServerId, NULL);
    DmtPrincipal principal( szDmServerId );

    DmtSessionProp prop(true);

    g_cancelSession = 0;

    ret_status = DmtTreeFactory::StartServerSession(principal, prop);
    
    jenv->ReleaseStringUTFChars(jServerId, szDmServerId);

    g_sessionObj = NULL;
    if (ret_status == SYNCML_DM_SUCCESS) {
        LOGV("Native startClientSession return successfully\n");
        return SYNCML_DM_SUCCESS;
    } else {
        LOGV("Native startClientSession return error %d\n", ret_status);
        return ret_status;
    }
}

JNIEXPORT jint JNICALL startFotaServerSession
  (JNIEnv *jenv, jclass jclz, jstring jServerId, jint sessionID, jobject jdmobj)
{
    LOGV("In native startFotaServerSession\n");

    g_sessionObj = jdmobj;

    const char* szDmServerId = jenv->GetStringUTFChars(jServerId, NULL);
    DmtPrincipal principal( szDmServerId );
    DmtSessionProp prop((UINT16)sessionID, true);

    g_cancelSession = 0;

    SYNCML_DM_RET_STATUS_T ret_status = DmtTreeFactory::StartServerSession(principal, prop);

    jenv->ReleaseStringUTFChars(jServerId, szDmServerId);

    g_sessionObj = NULL;

    if (ret_status == SYNCML_DM_SUCCESS) {
        LOGV("Native startFotaServerSession return successfully\n");
    } else {
        LOGV("Native startFotaServerSession return error %d\n", ret_status);
    }
    return ret_status;
}

JNIEXPORT jint JNICALL startFotaNotifySession(JNIEnv *jenv, jclass jclz,
        jstring result, jstring pkgURI, jstring alertType, 
        jstring serverID, jstring correlator, jobject jdmobj)
{
    g_sessionObj = jdmobj;

    const char* szResult = jenv->GetStringUTFChars(result, NULL);
    const char* szPkgURI = jenv->GetStringUTFChars(pkgURI, NULL);
    const char* szAlertType=jenv->GetStringUTFChars(alertType, NULL);
    const char* szDmServerId = jenv->GetStringUTFChars(serverID, NULL);
    const char* szCorrelator = jenv->GetStringUTFChars(correlator, NULL);

    DmtPrincipal principal(szDmServerId);
    DmtFirmAlert alert(szPkgURI, szResult, szAlertType, "chr", NULL, szCorrelator);
    DmtSessionProp prop(alert, true);

    SYNCML_DM_RET_STATUS_T dm_result = SYNCML_DM_SUCCESS;
    g_cancelSession = 0;

    dm_result = DmtTreeFactory::StartServerSession(principal, prop);

    jenv->ReleaseStringUTFChars(result, szResult);
    jenv->ReleaseStringUTFChars(pkgURI, szPkgURI);
    jenv->ReleaseStringUTFChars(alertType, szAlertType);
    jenv->ReleaseStringUTFChars(serverID, szDmServerId);
    jenv->ReleaseStringUTFChars(correlator, szCorrelator);

    g_sessionObj = NULL;
    if (dm_result == SYNCML_DM_SUCCESS) {
        LOGV("Native startFotaNotifySession return successfully\n");
        return SYNCML_DM_SUCCESS;
    } else {
        LOGV("Native startFotaNotifySession return error %d\n", dm_result);
        return dm_result;
    }
}

jobject getNetConnector()
{
    JNIEnv* env = android::AndroidRuntime::getJNIEnv();

    jclass jdmSessionClz = env->GetObjectClass(g_sessionObj);
    jmethodID jgetNet = env->GetMethodID(jdmSessionClz, 
            "getNetConnector", 
            "()Lcom/android/omadm/service/DMHttpConnector;");
    return env->CallObjectMethod(g_sessionObj, jgetNet);
}

jobject getDmAlert(JNIEnv *env)
{
   LOGD(("DM Alert: enter getDmAlert()"));
   if ( NULL == g_sessionObj ) {
       LOGE(("DM Alert: g_sessionObj is NULL!"));
       return NULL;
   }

   jclass jdmSessionClz = env->GetObjectClass(g_sessionObj);
   if ( NULL == jdmSessionClz ) {
       LOGE(("DM Alert: env->GetObjectClass(g_sessionObj) failed!"));
       return NULL;
   }
   LOGD(("DM Alert: success env->GetObjectClass(...)"));

   jmethodID jdmGetDmAlert = env->GetMethodID(jdmSessionClz, 
            "getDmAlert", 
            "()Lcom/android/omadm/service/DmAlert;");
   if ( NULL == jdmGetDmAlert ) {
       LOGE(("DM Alert: env->GetMethodID(jdmSessionClz) failed!"));
       return NULL;
   }
   LOGD(("DM Alert: success env->GetMethodID(...)"));

   return env->CallObjectMethod(g_sessionObj, jdmGetDmAlert);
}

JNIEXPORT jint JNICALL cancelSession(JNIEnv *jEnv, jclass jclz)
{
    g_cancelSession = 1;
    return SYNCML_DM_SUCCESS;
}

JNIEXPORT jstring JNICALL parseBootstrapServerId
  (JNIEnv *jenv, jclass, jbyteArray jMsgBuf, jboolean isWbxml)
{
    jint retCode = 0;
    jstring jServerId = NULL;
    
    SYNCML_DM_RET_STATUS_T dm_ret_status;
    
    jbyte* jBuf = jenv->GetByteArrayElements(jMsgBuf, NULL);
    jsize jBufSize = jenv->GetArrayLength(jMsgBuf);
    
    DmtPrincipal principal("DM_BOOTSTRAP");
    DMString strServerId;
    dm_ret_status = DmtTreeFactory::Bootstrap(principal, (const UINT8*)jBuf, jBufSize, isWbxml,
            false, strServerId);

    LOGD("parseBootstrapServerId dm_ret_status: %d", dm_ret_status);

    if (dm_ret_status == SYNCML_DM_SUCCESS && strServerId != NULL && strServerId.length() > 0) {
        LOGD("parseBootstrapServerId returns strServerId: %s", strServerId.c_str());
        jServerId = jenv->NewStringUTF(strServerId.c_str());
    }
                        
    return jServerId;
}

JNIEXPORT jint JNICALL processBootstrapScript
  (JNIEnv *jenv, jclass, jbyteArray jMsgBuf, jboolean isWbxml, jstring jServerId)
{
    SYNCML_DM_RET_STATUS_T dm_ret_status;
    const char* szDmServerId = jenv->GetStringUTFChars(jServerId, NULL);
    
    jbyte* jBuf = jenv->GetByteArrayElements(jMsgBuf, NULL);
    jsize jBufSize = jenv->GetArrayLength(jMsgBuf);
    
    DmtPrincipal principal("DM_BOOTSTRAP");
    DMString strServerId = szDmServerId;
    dm_ret_status = DmtTreeFactory::Bootstrap( 
                    principal, (const UINT8*)jBuf, jBufSize, isWbxml, true, strServerId);

    LOGD("processBootstrapScript dm_ret_status: %d", dm_ret_status);
          
    return dm_ret_status;
}


JNIEXPORT jbyteArray JNICALL processScript
  (JNIEnv *jenv, jclass, jstring jServerId, jstring jFileName, jboolean jIsBinary, jint jRetCode, jobject jdmobj)
{
  LOGV("In native processScript\n");
  g_sessionObj = jdmobj;

  jbyteArray jResult = NULL;
  SYNCML_DM_RET_STATUS_T ret_status;

  const char* szDmServerId = jenv->GetStringUTFChars(jServerId, NULL);

  if (szDmServerId == NULL) {
    ret_status = SYNCML_DM_DEVICE_FULL;
    SET_RET_STATUS_BUF;
    return jResult;
  }

  const char* szFileName = jenv->GetStringUTFChars(jFileName, NULL);
  if (szFileName == NULL) {
    jenv->ReleaseStringUTFChars(jServerId, szDmServerId);
    ret_status = SYNCML_DM_DEVICE_FULL;
    SET_RET_STATUS_BUF;
    return jResult;
  }

  LOGV("native processScript reading file <%s>\n", szFileName);

  FILE *fd = fopen(szFileName, "r");
  if (!fd) {
    LOGV("native processScript can't open file %s", szFileName);
    ret_status = SYNCML_DM_FILE_NOT_FOUND;
    SET_RET_STATUS_BUF;
    return jResult;
  }

  // assume 100k is enough
  const int c_nSize = 100 * 1024;
  char* szBuf = new char [c_nSize];

  if (szBuf == NULL) {
    ret_status = SYNCML_DM_DEVICE_FULL;
    SET_RET_STATUS_BUF;
    return jResult;
  }
    
  int buf_size = fread(szBuf, 1, c_nSize, fd );
  printf("native processScript read %d bytes, jIsBinary=%d\n", buf_size, jIsBinary);


  if ( buf_size > 0 ) {
    DmtPrincipal principal( szDmServerId );
    DMVector<UINT8> bResult;

    ret_status = DmtTreeFactory::ProcessScript(principal, (const UINT8*)szBuf, buf_size, jIsBinary, bResult);

    // copy bResult to jResult
    int resultSize = bResult.size();

    if (resultSize > 0) {
        Dump((const char*)bResult.get_data(), resultSize, jIsBinary);

        jResult = jenv->NewByteArray(resultSize);

        jenv->SetByteArrayRegion(jResult, 0, resultSize, (const jbyte*)bResult.get_data());
    }
    else {
        SET_RET_STATUS_BUF;
    }
  }
  else {
    // read 0 bytes from script file
    ret_status = SYNCML_DM_IO_FAILURE;
    SET_RET_STATUS_BUF;
  }

  // release memory allocated from GetStringUTFChars
  jenv->ReleaseStringUTFChars(jServerId, szDmServerId);
  jenv->ReleaseStringUTFChars(jFileName, szFileName);


  LOGV("Native processScript return code %d\n", ret_status);
  g_sessionObj = NULL;
  
  return jResult;
}


static JNINativeMethod gMethods[] = {
    {"initialize", "()I", (void*)initialize},
    {"destroy", "()I", (void*)destroy},
    {"parsePkg0", "([BLcom/android/omadm/service/DMPkg0Notification;)I", (void*)parsePkg0},
    {"startFotaClientSession",
        "(Ljava/lang/String;Ljava/lang/String;Lcom/android/omadm/service/DMSession;)I",
        (void*)startFotaClientSession},
    {"startFotaServerSession", "(Ljava/lang/String;ILcom/android/omadm/service/DMSession;)I",
        (void*)startFotaServerSession},
    {"startClientSession", "(Ljava/lang/String;Lcom/android/omadm/service/DMSession;)I",
        (void*)startClientSession},

    {"startFotaNotifySession",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/android/omadm/service/DMSession;)I",
        (void*)startFotaNotifySession},

    {"cancelSession", "()I", (void*)cancelSession},

    {"processScript",
        "(Ljava/lang/String;Ljava/lang/String;ZILcom/android/omadm/service/DMSession;)[B",
        (void*)processScript},
    {"processBootstrapScript", "([BZLjava/lang/String;)I", (void*)processBootstrapScript},
    {"parseBootstrapServerId", "([BZ)Ljava/lang/String;", (void*)parseBootstrapServerId},
};

int registerNatives(JNIEnv *env)
{
    jclass clazz = env->FindClass(javaDMEnginePackage);
    if (clazz == NULL)
        return JNI_FALSE;

    if (env->RegisterNatives(clazz, gMethods, sizeof(gMethods)/sizeof(gMethods[0])) < 0) {
        LOGE("registerNatives return ERROR");
        return JNI_FALSE;
    }

    registerDMTreeNatives(env);
    return JNI_TRUE;
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved)
{
    LOGD("In JNI_OnLoad");
    JNIEnv* env = android::AndroidRuntime::getJNIEnv();

    if (env == NULL) {
        LOGE("Get Environment Error");
        return -1;
    }

    return (registerNatives(env) == JNI_TRUE) ? JNI_VERSION_1_6 : -1;
}
