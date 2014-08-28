/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.omadm.service;

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

public class DMConfigureDB {
    private static final String TAG = "DMConfigureDB";
    private static final boolean DBG = DMClientService.DBG;

    private final DMClientService mContext;

    private static final String DATABASE_NAME = "DMConfigure.db";

    // FIXME: this and the other Sprint stuff *must* be moved to the SprintDM plugin.
    private static final String SPRINT_DM_SECRET = "dmsecret@sprint";

    private final SQLiteDatabase mdb;

    static final class AccountInfo {
        public String acctName;     // DM server account name
        public String serverID;     // DM server ID
        public String addr;         // DM server URL
        public String addrType;     // e.g. "URI"
        public String conRef;       // e.g. ""
        public String serverName;   // DM server name
        public String portNbr;      // DM server port, e.g. "443"
        public String serverNonce;  // HMAC server nonce
        public String serverPW;     // HMAC server password
        public String clientNonce;  // HMAC client nonce
        public String clientPW;     // HMAC client password
        public String userName;     // DM username (e.g. IMSI or MEID)
        public String authPref;     // e.g. "HMAC"
        public String proxyAddr;    // HTTP proxy address
        public String proxyPortNbr; // HTTP proxy port, e.g. "80"
    }

    public DMConfigureDB(DMClientService context) {
        mContext = context;
        mdb = mContext.openOrCreateDatabase(DATABASE_NAME, 0, null);
        Cursor cur = null;
        try {
            cur = mdb.rawQuery("PRAGMA table_info( dmAccounts )", null);
            int cnt = cur.getCount();
            if (DBG) logd("Cursor count for table dmAccounts is " + cnt);
            // TODO: we need a way for plugins to populate an empty table
            if (cnt == 0) {
                onCreate(mdb);
            }
            // NOTE: always update all the account info in DM tree
            loadDmConfig();
            loadDmAccount(mdb);
        } finally {
            if (cur != null) {
                cur.close();
            }
        }
    }

    public void closeDatabase() {
        mdb.close();
    }

    void onCreate(SQLiteDatabase db) {
        logd("onCreate");

        db.execSQL("CREATE TABLE dmAccounts (" +
                "_id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "ServerID TEXT UNIQUE ON CONFLICT REPLACE," +
                "AccName TEXT," +
                "Addr TEXT," +
                "AddrType TEXT," +
                "PortNbr TEXT," +
                "ConRef TEXT," +
                "Name TEXT," +
                "AuthPref TEXT," +
                "ServerPW TEXT," +
                "ServerNonce TEXT," +
                "UserName TEXT," +
                "ClientPW TEXT," +
                "ClientNonce TEXT," +
                "ProxyAddr TEXT," +
                "ProxyPortNbr TEXT" +
                ");");

        db.execSQL("CREATE TABLE dmFlexs (" +
                "_id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "name TEXT UNIQUE ON CONFLICT REPLACE," +
                "value TEXT" +
                ");");
    }

    public String getFotaServerID() {
        String id = getConfigField("PreferredServerID");

        if (id != null && !id.isEmpty()) {
            return id;
        }

        return getConfigField("FOTAServerID");
    }

    public boolean isDmAlertEnabled() {
        String value = getConfigField("DmAlertEnabled");
        return null == value || "true".equalsIgnoreCase(value);
    }

    public boolean isDmNonceResyncEnabled() {
        String value = getConfigField("DmNonceResyncEnabled");
        return null != value && "true".equalsIgnoreCase(value);
    }

    /*
     * Returns SyncML logging level
     * 0 = do not log syncml messages
     * 1 = log messages received as is
     * 2 = convert wbxml to xml messages and log it
     */
    public int getSyncMLLogLevel() {
        // FIXME always enable for now
        return 2;

//        String value = getConfigField("DmSyncMLLogLevel");
//        if (null == value) {
//            return 0;
//        }
//        return Integer.parseInt(value);
    }

    String getMeid() {
        TelephonyManager tm = (TelephonyManager)
                mContext.getSystemService(Context.TELEPHONY_SERVICE);

        // MEID is CDMA specific.
        if (tm.getPhoneType() != TelephonyManager.PHONE_TYPE_CDMA) {
          loge("getMeid called for non-CDMA phone!");
        }
        // MEID is 14 digits and convert hex digits to uppercase
        String devId = tm.getDeviceId();
        if (devId != null && devId.length() >= 14) {
            devId = devId.substring(0, 14).toUpperCase(Locale.US);
        }
        return devId;
    }

    private String getConfigField(String field) {
        String value = null;

        Cursor cr = mdb.query("dmFlexs", null, "name='" + field + '\'', null, null, null, null);

        if (cr != null) {
            if (cr.moveToFirst()) {
                int index = cr.getColumnIndex("value");
                value = cr.getString(index);
            }
            cr.close();
        }

        if (DBG) logd("get field '" + field + "'=" + value);
        return value;
    }

    public void setFotaServerID(String serverID) {
        ContentValues values = new ContentValues(1);

        //values.put("Name", "FOTAServerID");
        values.put("value", serverID);

        mdb.update("dmFlexs", values, "name='FOTAServerID'", null);
    }

    void setGsmImei(String imei) {
        ContentValues values = new ContentValues();
        values.put("name", "gsmImei");
        values.put("value", imei);
        mdb.insert("dmFlexs", null, values);

    }

    private void loadDmConfig() {
        //following statements just for debug print
        getConfigField("CarrierName");
        getConfigField("AdditionalCharge");
        getConfigField("PreferredServerID");

        // FIXME: this should be removed along with get/setGsmImei()
        if (DMSettingsHelper.isPhoneTypeLTE()) {
            SharedPreferences p = mContext.getSharedPreferences(DMHelper.IMEI_PREFERENCE_KEY, 0);
            String gsmImei = p.getString(DMHelper.IMEI_VALUE_KEY, null);
            if (DBG) logd("gsmImei in loadDmConfig is " + gsmImei);
            //ed.clear();
            if (null == gsmImei || gsmImei.isEmpty()) {
                // this is needed to avoid showing DMService app force close
                if (DBG) logd("set the imei value to zero");
                gsmImei = "0";
            } else if (gsmImei.length() > 15) {
                if (DBG) logd("imei length exceeding 15 digits so trim it to 15");
                gsmImei = gsmImei.substring(0, 15);
            }
            setGsmImei(gsmImei);
        }
        ///////////////////////////////////////////

    }

    private void loadDmAccount(SQLiteDatabase db) {
        AccountInfo ai = new AccountInfo();
        boolean isFirst = true;

        Cursor cr = db.rawQuery("SELECT * FROM dmAccounts", null);

        if (cr != null) {
            if (cr.moveToFirst()) {
                do {
                    ai.acctName = cr.getString(cr.getColumnIndex("AccName"));
                    if (DBG) logd("[Factory]account=" + ai.acctName);

                    ai.serverID = cr.getString(cr.getColumnIndex("ServerID"));
                    if (DBG) logd("[Factory]serverID=" + ai.serverID);

                    ai.addr = cr.getString(cr.getColumnIndex("Addr"));
                    if (DBG) logd("[Factory]addr=" + ai.addr);

                    ai.addrType = cr.getString(cr.getColumnIndex("AddrType"));
                    if (DBG) logd("[Factory]addrType=" + ai.addrType);

                    ai.portNbr = cr.getString(cr.getColumnIndex("PortNbr"));
                    if (DBG) logd("[Factory]portNbr=" + ai.portNbr);

                    ai.conRef = cr.getString(cr.getColumnIndex("ConRef"));
                    if (DBG) logd("[Factory]conRef=" + ai.conRef);

                    ai.serverName = cr.getString(cr.getColumnIndex("Name"));
                    if (DBG) logd("[Factory]serverName=" + ai.serverName);

                    ai.authPref = cr.getString(cr.getColumnIndex("AuthPref"));
                    if (DBG) logd("[Factory]authPref=" + ai.authPref);

                    ai.serverPW = cr.getString(cr.getColumnIndex("ServerPW"));
                    if (DBG) logd("[Factory]serverPW=" + ai.serverPW);

                    ai.serverNonce = cr.getString(cr.getColumnIndex("ServerNonce"));
                    if (DBG) logd("[Factory]serverNonce=" + ai.serverNonce);

                    ai.userName = cr.getString(cr.getColumnIndex("UserName"));
                    if (DBG) logd("[Factory]userName=" + ai.userName);

                    ai.clientPW = cr.getString(cr.getColumnIndex("ClientPW"));
                    if (DBG) logd("[Factory]clientPW=" + ai.clientPW);

                    ai.clientNonce = cr.getString(cr.getColumnIndex("ClientNonce"));
                    if (DBG) logd("[Factory]clientNonce=" + ai.clientNonce);

                    ai.proxyAddr = cr.getString(cr.getColumnIndex("ProxyAddr"));
                    if (DBG) logd("[Factory]proxyAddr=" + ai.proxyAddr);

                    ai.proxyPortNbr = cr.getString(cr.getColumnIndex("ProxyPortNbr"));
                    if (DBG) logd("[Factory]proxyPortNbr=" + ai.proxyPortNbr);

                    if (writeAccount2Dmt(ai) && isFirst) {
                        if (DBG) logd("[Factory]setFotaServerID: " + ai.serverID);

                        ContentValues values = new ContentValues();
                        values.put("name", "FOTAServerID");
                        values.put("value", ai.serverID);
                        db.insert("dmFlexs", null, values);

                        isFirst = false;
                    }

                } while (cr.moveToNext());

                cr.close();
                return;
            }
            cr.close();
        }

        try {
            XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
            factory.setNamespaceAware(true);
            XmlPullParser xpp = factory.newPullParser();

            InputStream in = getDMAccXmlInput();
            xpp.setInput(in, null);
            int eventType = xpp.getEventType();

            while (eventType != XmlPullParser.END_DOCUMENT) {
                if (eventType == XmlPullParser.START_TAG && "Account".equals(xpp.getName())) {
                    ai.acctName = xpp.getAttributeValue(null, "AccName");
                    if (DBG) logd("account=" + ai.acctName);

                    ai.serverID = xpp.getAttributeValue(null, "ServerID");
                    if (DBG) logd("serverID=" + ai.serverID);

                    ai.addr = getRealString(xpp.getAttributeValue(null, "Addr"));
                    if (DBG) logd("addr=" + ai.addr);

                    ai.addrType = xpp.getAttributeValue(null, "AddrType");
                    if (DBG) logd("addrType=" + ai.addrType);

                    ai.portNbr = xpp.getAttributeValue(null, "PortNbr");
                    if (DBG) logd("portNbr=" + ai.portNbr);

                    ai.conRef = xpp.getAttributeValue(null, "ConRef");
                    if (DBG) logd("conRef=" + ai.conRef);

                    ai.serverName = xpp.getAttributeValue(null, "ServerName");
                    if (DBG) logd("serverName=" + ai.serverName);

                    ai.authPref = xpp.getAttributeValue(null, "AuthPref");
                    if (DBG) logd("authPref=" + ai.authPref);

                    ai.serverPW = xpp.getAttributeValue(null, "ServerPW");
                    if (DBG) logd("serverPW=" + ai.serverPW);

                    ai.serverNonce = xpp.getAttributeValue(null, "ServerNonce");
                    if (DBG) logd("serverNonce=" + ai.serverNonce);

                    ai.userName = xpp.getAttributeValue(null, "UserName");
                    if (DBG) logd("userName=" + ai.userName);

                    ai.clientPW = xpp.getAttributeValue(null, "ClientPW");
                    if (DBG) logd("clientPW=" + ai.clientPW);

                    ai.clientNonce = xpp.getAttributeValue(null, "ClientNonce");
                    if (DBG) logd("clientNonce=" + ai.clientNonce);

                    ai.proxyAddr = getRealString(xpp.getAttributeValue(null, "ProxyAddr"));
                    if (DBG) logd("proxyAddr=" + ai.proxyAddr);

                    ai.proxyPortNbr = getRealString(xpp.getAttributeValue(null, "ProxyPortNbr"));
                    if (DBG) logd("addr=" + ai.proxyPortNbr);

                    // FIXME: check should be on account name instead of isFirst
                    if (writeAccount2Dmt(ai) && isFirst) {
                        if (DBG) logd("setFotaServerID: " + ai.serverID);

                        ContentValues values = new ContentValues();
                        values.put("name", "FOTAServerID");
                        values.put("value", ai.serverID);
                        db.insert("dmFlexs", null, values);
                        isFirst = false;
                    }
                }

                eventType = xpp.next();
            }

            in.close();

        } catch (IOException e) {
            loge("IOException in loadDmAccount", e);
        } catch (XmlPullParserException e) {
            loge("XmlPullParserException in loadDmAccount", e);
        }
    }

    private boolean writeAccount2Dmt(AccountInfo ai) {
        if (DBG) logd("enter writeAccount2Dmt");

        String acctName = ai.serverID;     // e.g. "sprint"; this is also the value for ServerID
        String dmServerNodePath = "./DMAcc/" + acctName;

        if (DBG) logd("XXX DELETING old server node path: " + dmServerNodePath);
        NativeDM.deleteNode(dmServerNodePath);

        if (NativeDM.createInterior(dmServerNodePath) != DMResult.SYNCML_DM_SUCCESS) {
            loge("createInterior '" + acctName + "' Error");
            return false;
        }

        if (NativeDM.createLeaf(dmServerNodePath + "/ServerID", ai.serverID)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createInterior '" + dmServerNodePath + "/ServerId" + "' Error");
            return false;
        }

        if (NativeDM.createLeaf(dmServerNodePath + "/AppID", "w7") != DMResult.SYNCML_DM_SUCCESS) {
            loge("createInterior '" + dmServerNodePath + "/AppID" + "' Error");
            return false;
        }

        if (NativeDM.createLeaf(dmServerNodePath + "/Name", ai.serverName)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmServerNodePath + "/Name" + "' Error");
            return false;
        }

        if (NativeDM.createLeaf(dmServerNodePath + "/PrefConRef", ai.conRef)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmServerNodePath + "/ConRef" + "' Error");
            return false;
        }

        if (NativeDM.createLeaf(dmServerNodePath + "/AAuthPref", ai.authPref)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmServerNodePath + "/AAuthPref" + "' Error");
            return false;
        }

        dmServerNodePath += "/AppAddr";
        if (NativeDM.createInterior(dmServerNodePath) != DMResult.SYNCML_DM_SUCCESS) {
            loge("createInterior '" + dmServerNodePath + "' Error");
            return false;
        }

        dmServerNodePath += "/1";   // limited to one server address per account

        if (NativeDM.createInterior(dmServerNodePath) != DMResult.SYNCML_DM_SUCCESS) {
            loge("createInterior '" + dmServerNodePath + "' Error");
            return false;
        }

        if ("sprint".equalsIgnoreCase(ai.serverID)) {
            String address = DMHelper.getServerUrl(mContext);
            if (!TextUtils.isEmpty(address)) {
                logd("Overriding server URL to: " + address);
                ai.addr = address;
            }
        }

        if (NativeDM.createLeaf(dmServerNodePath + "/Addr", ai.addr)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmServerNodePath + "/Addr" + "' Error");
            return false;
        }

        if (NativeDM.createLeaf(dmServerNodePath + "/AddrType", ai.addrType)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmServerNodePath + "/AddrType" + "' Error");
            return false;
        }

        dmServerNodePath += "/Port";
        if (NativeDM.createInterior(dmServerNodePath) != DMResult.SYNCML_DM_SUCCESS) {
            loge("createInterior '" + dmServerNodePath + "' Error");
            return false;
        }

        dmServerNodePath += "/1";   // limited to one port number per server address

        if (NativeDM.createInterior(dmServerNodePath) != DMResult.SYNCML_DM_SUCCESS) {
            loge("createInterior '" + dmServerNodePath + "' Error");
            return false;
        }

        if (NativeDM.createLeaf(dmServerNodePath + "/PortNbr", ai.portNbr)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmServerNodePath + "/PortNbr" + "' Error");
            return false;
        }

        // collection of authentication credentials
        dmServerNodePath = "./DMAcc/" + acctName + "/AppAuth";

        if (NativeDM.createInterior(dmServerNodePath) != DMResult.SYNCML_DM_SUCCESS) {
            loge("createInterior '" + dmServerNodePath + "' Error");
            return false;
        }

        // server credentials for authenticating the server from the OMA DM client
        dmServerNodePath += "/Server";

        if (NativeDM.createInterior(dmServerNodePath) != DMResult.SYNCML_DM_SUCCESS) {
            loge("createInterior '" + dmServerNodePath + "' Error");
            return false;
        }

        String authLevel = "SRVCRED";

        if (NativeDM.createLeaf(dmServerNodePath + "/AAuthLevel", authLevel)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmServerNodePath + "/AAuthLevel" + "' Error");
            return false;
        }

        if (NativeDM.createLeaf(dmServerNodePath + "/AAuthType", ai.authPref)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmServerNodePath + "/AAuthType" + "' Error");
            return false;
        }

        if (NativeDM.createLeaf(dmServerNodePath + "/AAuthName", acctName)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmServerNodePath + "/AAuthName" + "' Error");
            return false;
        }

        // FIXME: remove after adding code to push the account credentials from SprintDM
        if ("SPRINT".equals(ai.serverPW)) {
            ai.serverPW = sprintHashGenerator("sprint" + getMeid() + SPRINT_DM_SECRET);
            if (DBG) logd("sprintHashGenerator for server PW is " + ai.serverPW);
        }
        // FIXME: must remove the previous hack before ship!

        if (NativeDM.createLeaf(dmServerNodePath + "/AAuthSecret", ai.serverPW)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmServerNodePath + "/AAuthSecret" + "' Error");
            return false;
        }

        if (NativeDM.createLeaf(dmServerNodePath + "/AAuthData", ai.serverNonce)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmServerNodePath + "/AAuthData" + "' Error");
            return false;
        }

        // client credentials for authenticating ourselves to the OMA DM server
        String dmClientNodePath = "./DMAcc/" + acctName + "/AppAuth/Client";

        if (NativeDM.createInterior(dmClientNodePath) != DMResult.SYNCML_DM_SUCCESS) {
            loge("createInterior '" + dmServerNodePath + "' Error");
            return false;
        }

        String clientAuthLevel = "CLCRED";

        if (NativeDM.createLeaf(dmClientNodePath + "/AAuthLevel", clientAuthLevel)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmClientNodePath + "/AAuthLevel" + "' Error");
            return false;
        }

        String clientAuthType = ai.authPref;
        if (NativeDM.createLeaf(dmClientNodePath + "/AAuthType", clientAuthType)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmClientNodePath + "/AAuthType" + "' Error");
            return false;
        }

        // FIXME: remove this Sprint hack after SprintDM pushes the credentials to us
        if ("MEID".equals(ai.userName)) {
            ai.userName = getMeid();
            if (DBG) logd("FOR SPRINT: setting userName to " + ai.userName);
        }

        if (NativeDM.createLeaf(dmClientNodePath + "/AAuthName", ai.userName)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmClientNodePath + "/AAuthName" + "' Error");
            return false;
        }

        if ("SPRINT".equals(ai.clientPW)) {
            ai.clientPW = sprintHashGenerator(getMeid() + "sprint" + SPRINT_DM_SECRET);
            if (DBG) logd("sprintHashGenerator for client PW is " + ai.clientPW);
        }

        if (NativeDM.createLeaf(dmClientNodePath + "/AAuthSecret", ai.clientPW)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmClientNodePath + "/AAuthSecret" + "' Error");
            return false;
        }

        String clientNonce = ai.clientNonce;
        if (NativeDM.createLeaf(dmClientNodePath + "/AAuthData", clientNonce)
                != DMResult.SYNCML_DM_SUCCESS) {
            loge("createLeaf '" + dmClientNodePath + "/AAuthData" + "' Error");
            return false;
        }

        if (DBG) logd("leave writeAccount2Dmt: success");
        return true;
    }

    private InputStream getDMAccXmlInput() {
        try {
            File file = new File("/system/etc/", "dmAccounts.xml");
            InputStream in = new BufferedInputStream(new FileInputStream(file));
            if (DBG) logd("Load config from asset dmAccounts.xml");
            return in;
        } catch (IOException e) {
            loge("IOException in getDMAccXmlInput", e);
            return null;
        }
    }

    private String getRealString(String ins) {
        if (ins != null && !ins.isEmpty() && ins.charAt(0) == '$') {
            SharedPreferences prefs = mContext.getSharedPreferences("dmconfig", 0);
            String key = ins.substring(1);
            if (prefs.contains(key)) {
                return prefs.getString(key, "unknown");
            }
        }
        return ins;
    }

    private static String sprintHashGenerator(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(input.getBytes(), 0, input.length());
            String hash = Base64.encodeToString(digest.digest(),
                    Base64.NO_PADDING | Base64.NO_WRAP);
            hash = hash.replaceAll("\\+", "m").replaceAll("/", "f");
            return hash;
        } catch (NoSuchAlgorithmException e) {
            loge("can't find MD5 algorithm", e);
            return null;
        }
    }

//    private static void testSprintHashGenerator() {
//        String equip = "A000001A2B3C4F";
//        String server = "sprint";
//        String secret = "foobar";
//
//        Log.d(TAG, "XXXXX B64(MD5(\"foobar\") = " + sprintHashGenerator("foobar"));
//        Log.d(TAG, "XXXXX f(equip,server,secret) = " + sprintHashGenerator(equip + server + secret));
//        Log.d(TAG, "XXXXX f(server,equip,secret) = " + sprintHashGenerator(server + equip + secret));
//    }

    private static void logd(String msg) {
        Log.d(TAG, msg);
    }

    private static void loge(String msg) {
        Log.e(TAG, msg);
    }

    private static void loge(String msg, Throwable tr) {
        Log.d(TAG, msg, tr);
    }
}
